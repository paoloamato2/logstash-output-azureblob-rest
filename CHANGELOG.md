# Changelog

## 0.10.0
- Initial release of the REST-based Azure Blob output for Logstash 8.18+
- Replaces the `azure-storage-blob` dependency with direct Shared Key REST calls
- Adds optional gzip compression and batch sizing (`events_per_blob`)
