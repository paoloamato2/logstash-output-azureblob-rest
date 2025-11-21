# logstash-output-azureblob-rest

Custom Logstash output plugin that writes events to Azure Blob Storage using raw REST requests and Shared Key authentication.

## Why this fork exists
The upstream `logstash-output-azureblob` plugin relies on the `azure-storage-blob` Ruby gem. Starting with Logstash 8.18 (JRuby 9.4) that gem crashes during plugin initialisation with:

```
Java::JavaLang::ArrayIndexOutOfBoundsException: Index -1 out of bounds for length 754
```

To keep Logstash working we rewrote the output plugin so that it does not depend on the Azure SDK for Ruby. The new implementation speaks directly to the Blob Storage REST endpoints, preserving the original configuration schema (`storage_account_name`, `storage_access_key`, `container_name`, etc.).

## Installation
```
bin/logstash-plugin install https://github.com/paoloamato/logstash-output-azureblob-rest/releases/download/0.10.0/logstash-output-azureblob-rest-0.10.0.gem
```
(Replace the gem name with the exact version or package URL if you host it privately.)

## Configuration example
```ruby
output {
  azure_blob {
    storage_account_name => "mystorageaccount"
    storage_access_key   => "<access-key>"
    container_name       => "log-container"
    prefix               => "logs/%{+YYYY.MM.dd}"
    compress             => true
    events_per_blob      => 500
  }
}
```

## Features
- Compatible with Logstash 8.18+ / JRuby 9.4
- Optional gzip compression (`compress => true`)
- Batch control via `events_per_blob`
- Safer blob naming with timestamp + random suffix
- Built-in retry + non-fatal error handling (pipeline stays up if Azure rejects uploads)
- Shared Key request signing (no extra gems required)

## Failure handling
- HTTP 5xx / 429 / 408 responses and transient connection errors are retried a few times with backoff.
- Non-retriable errors (for example 403 authorization failures) are logged and the batch is dropped, but the pipeline worker keeps running.

## Reliability tuning (optional)
- `retry_max_attempts` (default: 3)
- `retry_delay_seconds` (default: 2) with per-attempt linear backoff
- `retry_max_delay_seconds` (default: 0 = uncapped)
- `http_open_timeout_seconds` (default: 10)
- `http_read_timeout_seconds` (default: 60)
- `log_response_bytes` (default: 2048) to cap how much of the error body is logged

## Development
```
bundle install
bundle exec rspec
bundle exec gem build logstash-output-azureblob-rest.gemspec
```

## License
Apache 2.0
