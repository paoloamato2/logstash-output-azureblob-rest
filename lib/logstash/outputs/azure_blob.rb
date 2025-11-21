require 'logstash/outputs/base'
require 'logstash/namespace'
require 'logstash/outputs/azure_blob/version'
require 'securerandom'
require 'time'
require 'stringio'
require 'zlib'
require 'base64'
require 'openssl'
require 'net/http'
require 'uri'

class LogStash::Outputs::LogstashAzureBlobOutput < LogStash::Outputs::Base
  config_name 'azure_blob'
  default :codec, 'line'

  config :storage_account_name, validate: :string, required: true
  config :storage_access_key, validate: :string, required: true
  config :container_name, validate: :string, required: true

  config :prefix, validate: :string, default: ''
  config :file_extension, validate: :string, default: '.log'
  config :compress, validate: :boolean, default: false
  config :events_per_blob, validate: :number, default: 0
  config :content_type, validate: :string, default: 'text/plain; charset=utf-8'

  def register
    @logger.info('Azure blob output: initialising client', account: storage_account_name, container: container_name)
    @blob_client = SharedKeyClient.new(storage_account_name, storage_access_key, @logger)
    @blob_client.ensure_container(container_name)

    @sanitised_prefix = sanitise_path(@prefix)
    @file_extension = normalise_extension(@file_extension)
  end

  def multi_receive_encoded(events_and_encoded)
    return if events_and_encoded.empty?

    split_batches(events_and_encoded).each do |batch|
      upload_batch(batch)
    end
  end

  private

  def upload_batch(batch)
    blob_name = nil
    event = batch.first.first
    blob_name = build_blob_name(event)
    payload = serialise_payload(batch)

    @blob_client.upload_block_blob(@container_name, blob_name, payload, content_type: resolved_content_type)
    @logger.info('Azure blob output: uploaded blob', blob: blob_name, bytes: payload.bytesize)
  rescue SharedKeyClient::RequestError => e
    @logger.error(
      'Azure blob output: request failed, dropping batch',
      blob: blob_name,
      status: e.status,
      request_id: e.request_id,
      response_body: truncate_body(e.body)
    )
  rescue => e
    @logger.error(
      'Azure blob output: unexpected failure, dropping batch',
      blob: blob_name,
      error: e.message,
      class: e.class.name,
      backtrace: e.backtrace&.take(10)
    )
  end

  def resolved_content_type
    return 'application/octet-stream' if @compress
    @content_type
  end

  def split_batches(events_and_encoded)
    return [events_and_encoded] if @events_per_blob.nil? || @events_per_blob <= 0
    events_and_encoded.each_slice(@events_per_blob).to_a
  end

  def serialise_payload(batch)
    data = batch.map { |_, encoded| encoded }.join
    return data unless @compress

    buffer = StringIO.new
    Zlib::GzipWriter.wrap(buffer) { |gz| gz.write(data) }
    buffer.string
  end

  def build_blob_name(event)
    timestamp = extract_timestamp(event)
    parts = []
    parts << @sanitised_prefix unless @sanitised_prefix.empty?
    parts << timestamp.strftime('%Y/%m/%d')
    basename = [timestamp.strftime('%H%M%S'), SecureRandom.hex(8)].join('-')
    parts << (basename + @file_extension)
    parts.join('/').gsub(%r{/+}, '/').sub(%r{^/}, '')
  end

  def extract_timestamp(event)
    ts = event.get('@timestamp')
    ts = ts.time if ts.respond_to?(:time)
    (ts || Time.now).utc
  rescue StandardError
    Time.now.utc
  end

  INVALID_PATH_CHARS = /["'\\?#%\u0000-\u001f]/.freeze

  def sanitise_path(value)
    value = value.to_s.strip
    return '' if value.empty?

    value.split('/').reject(&:empty?).map do |segment|
      segment.gsub(INVALID_PATH_CHARS, '_')
    end.join('/')
  end

  def normalise_extension(ext)
    value = ext.to_s.strip
    value = '.log' if value.empty?
    value = '.' + value unless value.start_with?('.')
    value += '.gz' if @compress && !value.end_with?('.gz')
    value
  end

  MAX_RESPONSE_LOG_BYTES = 2048

  def truncate_body(body)
    return nil if body.nil?
    return body if body.bytesize <= MAX_RESPONSE_LOG_BYTES

    body.byteslice(0, MAX_RESPONSE_LOG_BYTES) + '... [truncated]'
  rescue StandardError
    body.to_s[0, MAX_RESPONSE_LOG_BYTES]
  end

  class SharedKeyClient
    API_VERSION = '2020-10-02'.freeze
    RETRYABLE_STATUS = ([408, 429] + (500..599).to_a).freeze
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 2
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 60

    class RequestError < StandardError
      attr_reader :status, :body, :request_id

      def initialize(message, status:, body:, request_id: nil)
        super(message)
        @status = status
        @body = body
        @request_id = request_id
      end
    end

    def initialize(account, access_key, logger)
      @account = account
      @key = Base64.decode64(access_key)
      @logger = logger
    end

    def ensure_container(container)
      uri = URI::HTTPS.build(host: host, path: "/#{container}", query: 'restype=container')
      request = Net::HTTP::Put.new(uri)
      request['Content-Length'] = '0'
      request['Content-Type'] = ''
      add_common_headers(request)
      request['Authorization'] = authorization('PUT', uri, request)
      send_request(uri, request, acceptable: [200, 201, 202, 409])
    end

    def upload_block_blob(container, blob_name, body, content_type: 'application/octet-stream')
      uri = URI::HTTPS.build(host: host, path: "/#{container}/#{blob_name}")
      request = Net::HTTP::Put.new(uri)
      request['Content-Length'] = body.bytesize.to_s
      request['Content-Type'] = content_type
      request['x-ms-blob-type'] = 'BlockBlob'
      add_common_headers(request)
      request.body = body
      request['Authorization'] = authorization('PUT', uri, request)
      send_request(uri, request, acceptable: [200, 201])
    end

    private

    def host
      "#{@account}.blob.core.windows.net"
    end

    def add_common_headers(request)
      request['x-ms-date'] = Time.now.utc.httpdate
      request['x-ms-version'] = API_VERSION
    end

    def send_request(uri, request, acceptable: [200])
      attempts = 0

      begin
        attempts += 1
        Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
          response = http.request(request)
          status = response.code.to_i
          return response if acceptable.include?(status)

          raise RequestError.new(
            "Azure request failed: #{status}",
            status: status,
            body: response.body,
            request_id: response['x-ms-request-id']
          )
        end
      rescue RequestError => e
        if retryable_status?(e.status) && attempts <= MAX_RETRIES
          delay = retry_delay(attempts)
          @logger.warn('Azure blob output: retrying after HTTP failure', status: e.status, request_id: e.request_id, attempt: attempts, delay: delay)
          sleep(delay)
          retry
        end
        raise
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNRESET => e
        if attempts <= MAX_RETRIES
          delay = retry_delay(attempts)
          @logger.warn('Azure blob output: retrying after connection failure', error: e.message, attempt: attempts, delay: delay)
          sleep(delay)
          retry
        end
        raise
      end
    end

    def authorization(verb, uri, request)
      canonical_headers = canonicalize_headers(request)
      canonical_resource = canonicalize_resource(uri)
      content_length = request['Content-Length'] || ''
      content_length = '' if verb.upcase == 'GET' || content_length == '0'

      string_to_sign = [
        verb.upcase,
        request['Content-Encoding'] || '',
        request['Content-Language'] || '',
        content_length,
        request['Content-MD5'] || '',
        request['Content-Type'] || '',
        '', '', '', '', '', '',
        canonical_headers,
        canonical_resource
      ].join("\n")

      signature = Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', @key, string_to_sign))
      "SharedKey #{@account}:#{signature}"
    end

    def canonicalize_headers(request)
      request.each_header
             .select { |k, _| k.start_with?('x-ms-') }
             .sort_by { |k, _| k }
             .map { |k, v| "#{k.downcase}:#{v.strip}" }
             .join("\n")
    end

    def canonicalize_resource(uri)
      resource = "/#{@account}#{uri.path}"
      if uri.query
        params = URI.decode_www_form(uri.query).group_by { |k, _| k.downcase }
        param_str = params.sort.map do |key, values|
          "#{key}:#{values.map { |(_, v)| v }.sort.join(',')}"
        end.join("\n")
        resource += "\n" + param_str unless param_str.empty?
      end
      resource
    end

    def retryable_status?(status)
      RETRYABLE_STATUS.include?(status)
    end

    def retry_delay(attempt)
      RETRY_DELAY_SECONDS * attempt
    end
  end
end
