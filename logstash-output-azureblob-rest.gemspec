# frozen_string_literal: true

require_relative 'lib/logstash/outputs/azure_blob/version'

Gem::Specification.new do |spec|
  spec.name          = 'logstash-output-azureblob-rest'
  spec.version       = LogstashOutputAzureBlobRest::VERSION
  spec.authors       = ['Paolo Amato']
  spec.email         = ['paoloamato1313@gmail.com']

  spec.summary       = 'Logstash output plugin that uploads events to Azure Blob Storage using REST API calls.'
  spec.description   = <<~DESC
    Drop-in replacement for the legacy logstash-output-azureblob plugin. Implements uploads via the Azure Blob REST API
    to remain compatible with Logstash 8.18+ (JRuby 9.4), avoiding the crashes caused by the azure-storage-blob gem.
  DESC
  spec.homepage      = 'https://github.com/paoloamato2/logstash-output-azureblob-rest'
  spec.license       = 'Apache-2.0'

  spec.metadata['logstash_plugin'] = 'true'
  spec.metadata['logstash_group'] = 'output'
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['homepage_uri'] = spec.homepage

  spec.files         = Dir.glob('lib/**/*') + %w[Gemfile README.md CHANGELOG.md LICENSE]
  spec.require_paths = ['lib']

  spec.add_dependency 'logstash-core-plugin-api', '>= 2.0', '<= 2.99'

  spec.add_development_dependency 'bundler', '>= 1.17'
  spec.add_development_dependency 'rspec'
end
