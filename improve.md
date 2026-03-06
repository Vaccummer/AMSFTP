Give me a concrete and detailed plan:
include/infrastructure/Config.hpp
AMInfraConfigManager needs to refactor:

1. domain layer ConfigManager

init with dict<DocumentKind, tuple<json_path, schema_path, schema_data_str>> and AsyncWriteSchedulerPort

hold a dict <DocumentKind, DocumentState>
DocumentState add an attr to store schema string data(cause in the last stage, i will hard code schema in the programm, schema path is actually schema_data output path)
implement functions has similar signatures to SuperHandlePort:
for example:
Json read/write function add an extra arg  DocumentKind
Json dump function add arg  DocumentKind and bool async


2. json data detach port

some classed may directly read Json
