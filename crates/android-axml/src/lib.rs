use std::fmt;

use serde::{Deserialize, Serialize};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = 0xffff_ffff;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;
const SORTED_FLAG: u32 = 0x0000_0001;
const ANDROID_NAMESPACE_URI: &str = "http://schemas.android.com/apk/res/android";
const ANDROID_ATTR_NAME: u32 = 0x0101_0003;
const ANDROID_ATTR_EXPORTED: u32 = 0x0101_0010;
const ANDROID_ATTR_AUTHORITIES: u32 = 0x0101_0018;
const ANDROID_ATTR_INIT_ORDER: u32 = 0x0101_001a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxmlError {
    Invalid(&'static str),
    Truncated(&'static str),
}

impl fmt::Display for AxmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AxmlError::Invalid(message) => write!(f, "invalid binary Android manifest: {message}"),
            AxmlError::Truncated(message) => {
                write!(f, "truncated binary Android manifest: {message}")
            }
        }
    }
}

impl std::error::Error for AxmlError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AndroidManifest {
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<u32>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub application_class: Option<String>,
    pub extract_native_libs: Option<bool>,
    pub main_activity: Option<String>,
    pub providers: Vec<ProviderDeclaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderDeclaration {
    pub name: Option<String>,
    pub authorities: Option<String>,
    pub exported: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestProvider {
    pub name: String,
    pub authorities: String,
    pub exported: bool,
    pub init_order: Option<i32>,
}

pub fn bootstrap_provider_authority(package_name: &str, build_id: &str) -> String {
    let suffix: String = build_id.chars().take(8).collect();
    format!("{package_name}.rasp.{suffix}")
}

pub fn inject_manifest_provider(
    bytes: &[u8],
    provider: &ManifestProvider,
) -> Result<Vec<u8>, AxmlError> {
    validate_provider(provider)?;

    let parsed_manifest = parse_manifest(bytes)?;
    if parsed_manifest.providers.iter().any(|existing| {
        existing.name.as_deref() == Some(provider.name.as_str())
            || existing.authorities.as_deref() == Some(provider.authorities.as_str())
    }) {
        return Err(AxmlError::Invalid("bootstrap provider already exists"));
    }

    let root = read_chunk_header(bytes, 0)?;
    if root.chunk_type != RES_XML_TYPE {
        return Err(AxmlError::Invalid("root chunk is not binary XML"));
    }
    let root_end = checked_chunk_end(bytes, 0, root.size)?;
    let string_pool_offset = find_required_chunk_offset(
        bytes,
        root.header_size as usize,
        root_end,
        RES_STRING_POOL_TYPE,
    )?;
    let string_pool_header = read_chunk_header(bytes, string_pool_offset)?;
    let string_pool_end = checked_chunk_end(bytes, string_pool_offset, string_pool_header.size)?;
    let string_pool = parse_string_pool_details(bytes, string_pool_offset, &string_pool_header)?;
    let resource_map_offset =
        find_optional_chunk_offset(bytes, string_pool_end, root_end, RES_XML_RESOURCE_MAP_TYPE)?;
    let resource_map = match resource_map_offset {
        Some(offset) => {
            let header = read_chunk_header(bytes, offset)?;
            parse_resource_map(bytes, offset, &header)?
        }
        None => Vec::new(),
    };
    let application_end_offset = find_application_end_offset(
        bytes,
        root.header_size as usize,
        root_end,
        &string_pool.strings,
    )?;

    let mut strings = string_pool.strings.clone();
    let android_namespace_index = get_or_push_string(&mut strings, ANDROID_NAMESPACE_URI)?;
    let provider_element_index = get_or_push_string(&mut strings, "provider")?;
    let name_attr_index = get_or_push_string(&mut strings, "name")?;
    let exported_attr_index = get_or_push_string(&mut strings, "exported")?;
    let authorities_attr_index = get_or_push_string(&mut strings, "authorities")?;
    let init_order_attr_index = if provider.init_order.is_some() {
        Some(get_or_push_string(&mut strings, "initOrder")?)
    } else {
        None
    };
    let provider_name_index = get_or_push_string(&mut strings, &provider.name)?;
    let provider_authorities_index = get_or_push_string(&mut strings, &provider.authorities)?;

    let mut resource_ids = resource_map;
    if resource_ids.len() < strings.len() {
        resource_ids.resize(strings.len(), 0);
    }
    resource_ids[name_attr_index as usize] = ANDROID_ATTR_NAME;
    resource_ids[exported_attr_index as usize] = ANDROID_ATTR_EXPORTED;
    resource_ids[authorities_attr_index as usize] = ANDROID_ATTR_AUTHORITIES;
    if let Some(index) = init_order_attr_index {
        resource_ids[index as usize] = ANDROID_ATTR_INIT_ORDER;
    }

    let rebuilt_string_pool = build_string_pool(&string_pool, &strings)?;
    let rebuilt_resource_map = build_resource_map(&resource_ids)?;
    let provider_chunks = build_provider_chunks(ProviderChunkIndexes {
        android_namespace_index,
        provider_element_index,
        name_attr_index,
        exported_attr_index,
        authorities_attr_index,
        init_order_attr_index,
        provider_name_index,
        provider_authorities_index,
        exported: provider.exported,
        init_order: provider.init_order,
    })?;

    let mut output = Vec::with_capacity(
        bytes.len()
            + rebuilt_string_pool.len()
            + rebuilt_resource_map.len()
            + provider_chunks.len(),
    );
    output.extend_from_slice(&bytes[..string_pool_offset]);
    output.extend_from_slice(&rebuilt_string_pool);

    let mut offset = string_pool_end;
    let mut wrote_resource_map = false;
    while offset < root_end {
        let header = read_chunk_header(bytes, offset)?;
        let chunk_end = checked_chunk_end(bytes, offset, header.size)?;

        if !wrote_resource_map {
            if Some(offset) == resource_map_offset {
                output.extend_from_slice(&rebuilt_resource_map);
                wrote_resource_map = true;
                offset = chunk_end;
                continue;
            }
            if resource_map_offset.is_none() {
                output.extend_from_slice(&rebuilt_resource_map);
                wrote_resource_map = true;
            }
        }

        if offset == application_end_offset {
            output.extend_from_slice(&provider_chunks);
        }
        output.extend_from_slice(&bytes[offset..chunk_end]);
        offset = chunk_end;
    }

    let output_size = to_u32(output.len(), "binary XML size")?;
    write_u32_at(&mut output, 4, output_size)?;
    Ok(output)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<AndroidManifest, AxmlError> {
    let root = read_chunk_header(bytes, 0)?;
    let (mut offset, end) = if root.chunk_type == RES_XML_TYPE {
        (
            root.header_size as usize,
            checked_chunk_end(bytes, 0, root.size)?,
        )
    } else {
        (0, bytes.len())
    };

    let mut strings = Vec::new();
    let mut parser_state = ManifestParserState::default();

    while offset < end {
        let header = read_chunk_header(bytes, offset)?;
        let chunk_end = checked_chunk_end(bytes, offset, header.size)?;
        match header.chunk_type {
            RES_STRING_POOL_TYPE => {
                strings = parse_string_pool(bytes, offset, &header)?;
            }
            RES_XML_RESOURCE_MAP_TYPE => {}
            RES_XML_START_ELEMENT_TYPE => {
                apply_start_element(bytes, offset, &header, &strings, &mut parser_state)?;
            }
            RES_XML_END_ELEMENT_TYPE => {
                apply_end_element(bytes, offset, &strings, &mut parser_state)?;
            }
            _ => {}
        }
        offset = chunk_end;
    }

    Ok(parser_state.manifest)
}

fn apply_start_element(
    bytes: &[u8],
    offset: usize,
    header: &ChunkHeader,
    strings: &[String],
    state: &mut ManifestParserState,
) -> Result<(), AxmlError> {
    if header.header_size < 16 {
        return Err(AxmlError::Invalid("start element header is too small"));
    }

    let extension_offset = offset
        .checked_add(16)
        .ok_or(AxmlError::Invalid("start element offset overflow"))?;
    require_len(bytes, extension_offset, 20, "start element extension")?;

    let element_name = string_at(strings, read_u32(bytes, extension_offset + 4)?)
        .unwrap_or_default()
        .to_string();
    let attribute_start = read_u16(bytes, extension_offset + 8)? as usize;
    let attribute_size = read_u16(bytes, extension_offset + 10)? as usize;
    let attribute_count = read_u16(bytes, extension_offset + 12)? as usize;
    if attribute_size < 20 {
        return Err(AxmlError::Invalid("attribute size is too small"));
    }

    let attributes_offset = extension_offset
        .checked_add(attribute_start)
        .ok_or(AxmlError::Invalid("attribute offset overflow"))?;
    let mut attributes = Vec::with_capacity(attribute_count);
    for index in 0..attribute_count {
        let attribute_offset = attributes_offset
            .checked_add(index.saturating_mul(attribute_size))
            .ok_or(AxmlError::Invalid("attribute index overflow"))?;
        require_len(bytes, attribute_offset, 20, "attribute")?;
        let name = string_at(strings, read_u32(bytes, attribute_offset + 4)?)
            .unwrap_or_default()
            .to_string();
        let raw_value_index = read_u32(bytes, attribute_offset + 8)?;
        let value_type = read_u8(bytes, attribute_offset + 15)?;
        let value_data = read_u32(bytes, attribute_offset + 16)?;
        let value = decode_attribute_value(strings, raw_value_index, value_type, value_data);
        attributes.push((name, value));
    }

    match element_name.as_str() {
        "manifest" => {
            state.manifest.package_name = attr_string(&attributes, "package");
            state.manifest.version_name = attr_string(&attributes, "versionName");
            state.manifest.version_code = attr_u32(&attributes, "versionCode");
        }
        "uses-sdk" => {
            state.manifest.min_sdk = attr_u32(&attributes, "minSdkVersion");
            state.manifest.target_sdk = attr_u32(&attributes, "targetSdkVersion");
        }
        "application" => {
            state.manifest.application_class = attr_string(&attributes, "name");
            state.manifest.extract_native_libs = attr_bool(&attributes, "extractNativeLibs");
        }
        "provider" => {
            state.manifest.providers.push(ProviderDeclaration {
                name: attr_string(&attributes, "name"),
                authorities: attr_string(&attributes, "authorities"),
                exported: attr_bool(&attributes, "exported"),
            });
        }
        "action"
            if is_inside_intent_filter(&state.stack)
                && attr_string(&attributes, "name").as_deref()
                    == Some("android.intent.action.MAIN") =>
        {
            if let Some(activity) = nearest_activity_mut(&mut state.stack) {
                activity.has_main_action = true;
            }
        }
        "category"
            if is_inside_intent_filter(&state.stack)
                && attr_string(&attributes, "name").as_deref()
                    == Some("android.intent.category.LAUNCHER") =>
        {
            if let Some(activity) = nearest_activity_mut(&mut state.stack) {
                activity.has_launcher_category = true;
            }
        }
        _ => {}
    }

    let activity = if matches!(element_name.as_str(), "activity" | "activity-alias") {
        attr_string(&attributes, "name").map(|name| ActivityCandidate {
            name,
            has_main_action: false,
            has_launcher_category: false,
        })
    } else {
        None
    };

    state.stack.push(ElementFrame {
        name: element_name,
        activity,
    });

    Ok(())
}

fn apply_end_element(
    bytes: &[u8],
    offset: usize,
    strings: &[String],
    state: &mut ManifestParserState,
) -> Result<(), AxmlError> {
    require_len(bytes, offset, 24, "end element")?;
    let element_name = string_at(strings, read_u32(bytes, offset + 20)?)
        .unwrap_or_default()
        .to_string();

    let Some(frame) = state.stack.pop() else {
        return Ok(());
    };

    let ending_activity = matches!(element_name.as_str(), "activity" | "activity-alias")
        || matches!(frame.name.as_str(), "activity" | "activity-alias");
    if ending_activity {
        if let Some(activity) = frame.activity {
            if state.manifest.main_activity.is_none()
                && activity.has_main_action
                && activity.has_launcher_category
            {
                state.manifest.main_activity = Some(activity.name);
            }
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct ManifestParserState {
    manifest: AndroidManifest,
    stack: Vec<ElementFrame>,
}

#[derive(Debug)]
struct ElementFrame {
    name: String,
    activity: Option<ActivityCandidate>,
}

#[derive(Debug)]
struct ActivityCandidate {
    name: String,
    has_main_action: bool,
    has_launcher_category: bool,
}

fn is_inside_intent_filter(stack: &[ElementFrame]) -> bool {
    stack
        .iter()
        .rev()
        .any(|frame| frame.name == "intent-filter")
}

fn nearest_activity_mut(stack: &mut [ElementFrame]) -> Option<&mut ActivityCandidate> {
    stack
        .iter_mut()
        .rev()
        .find_map(|frame| frame.activity.as_mut())
}

fn decode_attribute_value(
    strings: &[String],
    raw_value_index: u32,
    value_type: u8,
    value_data: u32,
) -> Option<AttributeValue> {
    if raw_value_index != NO_INDEX {
        return string_at(strings, raw_value_index)
            .map(ToString::to_string)
            .map(AttributeValue::String);
    }

    match value_type {
        TYPE_STRING => string_at(strings, value_data)
            .map(ToString::to_string)
            .map(AttributeValue::String),
        TYPE_INT_DEC | TYPE_INT_HEX => Some(AttributeValue::Integer(value_data)),
        TYPE_INT_BOOLEAN => Some(AttributeValue::Bool(value_data != 0)),
        _ => None,
    }
}

fn attr_string(attributes: &[(String, Option<AttributeValue>)], name: &str) -> Option<String> {
    attributes
        .iter()
        .find(|(attribute_name, _)| attribute_name == name)
        .and_then(|(_, value)| match value {
            Some(AttributeValue::String(value)) => Some(value.clone()),
            Some(AttributeValue::Integer(value)) => Some(value.to_string()),
            Some(AttributeValue::Bool(value)) => Some(value.to_string()),
            None => None,
        })
}

fn attr_u32(attributes: &[(String, Option<AttributeValue>)], name: &str) -> Option<u32> {
    attributes
        .iter()
        .find(|(attribute_name, _)| attribute_name == name)
        .and_then(|(_, value)| match value {
            Some(AttributeValue::Integer(value)) => Some(*value),
            Some(AttributeValue::String(value)) => value.parse().ok(),
            _ => None,
        })
}

fn attr_bool(attributes: &[(String, Option<AttributeValue>)], name: &str) -> Option<bool> {
    attributes
        .iter()
        .find(|(attribute_name, _)| attribute_name == name)
        .and_then(|(_, value)| match value {
            Some(AttributeValue::Bool(value)) => Some(*value),
            Some(AttributeValue::Integer(value)) => Some(*value != 0),
            Some(AttributeValue::String(value)) => value.parse().ok(),
            _ => None,
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttributeValue {
    String(String),
    Integer(u32),
    Bool(bool),
}

fn parse_string_pool(
    bytes: &[u8],
    offset: usize,
    header: &ChunkHeader,
) -> Result<Vec<String>, AxmlError> {
    if header.header_size < 28 {
        return Err(AxmlError::Invalid("string pool header is too small"));
    }

    let string_count = read_u32(bytes, offset + 8)? as usize;
    let flags = read_u32(bytes, offset + 16)?;
    let strings_start = read_u32(bytes, offset + 20)? as usize;
    let offsets_start = offset
        .checked_add(header.header_size as usize)
        .ok_or(AxmlError::Invalid("string offsets overflow"))?;
    let string_data_start = offset
        .checked_add(strings_start)
        .ok_or(AxmlError::Invalid("string data offset overflow"))?;
    let chunk_end = checked_chunk_end(bytes, offset, header.size)?;

    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let string_offset_index = offsets_start
            .checked_add(index.saturating_mul(4))
            .ok_or(AxmlError::Invalid("string offset index overflow"))?;
        let string_offset = read_u32(bytes, string_offset_index)? as usize;
        let string_start = string_data_start
            .checked_add(string_offset)
            .ok_or(AxmlError::Invalid("string offset overflow"))?;
        if string_start >= chunk_end {
            return Err(AxmlError::Truncated("string data"));
        }

        let value = if flags & UTF8_FLAG != 0 {
            parse_utf8_string(bytes, string_start, chunk_end)?
        } else {
            parse_utf16_string(bytes, string_start, chunk_end)?
        };
        strings.push(value);
    }

    Ok(strings)
}

fn parse_utf8_string(bytes: &[u8], offset: usize, chunk_end: usize) -> Result<String, AxmlError> {
    let (_, utf16_len_size) = decode_length8(bytes, offset, chunk_end)?;
    let length_offset = offset
        .checked_add(utf16_len_size)
        .ok_or(AxmlError::Invalid("UTF-8 length offset overflow"))?;
    let (byte_len, byte_len_size) = decode_length8(bytes, length_offset, chunk_end)?;
    let data_offset = length_offset
        .checked_add(byte_len_size)
        .ok_or(AxmlError::Invalid("UTF-8 data offset overflow"))?;
    require_len(bytes, data_offset, byte_len, "UTF-8 string")?;
    let data_end = data_offset
        .checked_add(byte_len)
        .ok_or(AxmlError::Invalid("UTF-8 string end overflow"))?;
    if data_end > chunk_end {
        return Err(AxmlError::Truncated("UTF-8 string"));
    }

    Ok(String::from_utf8_lossy(&bytes[data_offset..data_end]).into_owned())
}

fn parse_utf16_string(bytes: &[u8], offset: usize, chunk_end: usize) -> Result<String, AxmlError> {
    let (char_len, len_size) = decode_length16(bytes, offset, chunk_end)?;
    let data_offset = offset
        .checked_add(len_size)
        .ok_or(AxmlError::Invalid("UTF-16 data offset overflow"))?;
    let byte_len = char_len
        .checked_mul(2)
        .ok_or(AxmlError::Invalid("UTF-16 byte length overflow"))?;
    require_len(bytes, data_offset, byte_len, "UTF-16 string")?;
    let data_end = data_offset
        .checked_add(byte_len)
        .ok_or(AxmlError::Invalid("UTF-16 string end overflow"))?;
    if data_end > chunk_end {
        return Err(AxmlError::Truncated("UTF-16 string"));
    }

    let mut chars = Vec::with_capacity(char_len);
    for index in 0..char_len {
        chars.push(read_u16(bytes, data_offset + index * 2)?);
    }
    Ok(String::from_utf16_lossy(&chars))
}

fn decode_length8(
    bytes: &[u8],
    offset: usize,
    chunk_end: usize,
) -> Result<(usize, usize), AxmlError> {
    if offset >= chunk_end {
        return Err(AxmlError::Truncated("UTF-8 length"));
    }
    let first = read_u8(bytes, offset)?;
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else {
        if offset + 1 >= chunk_end {
            return Err(AxmlError::Truncated("UTF-8 extended length"));
        }
        let second = read_u8(bytes, offset + 1)?;
        Ok(((((first & 0x7f) as usize) << 8) | second as usize, 2))
    }
}

fn decode_length16(
    bytes: &[u8],
    offset: usize,
    chunk_end: usize,
) -> Result<(usize, usize), AxmlError> {
    if offset + 1 >= chunk_end {
        return Err(AxmlError::Truncated("UTF-16 length"));
    }
    let first = read_u16(bytes, offset)?;
    if first & 0x8000 == 0 {
        Ok((first as usize, 2))
    } else {
        if offset + 3 >= chunk_end {
            return Err(AxmlError::Truncated("UTF-16 extended length"));
        }
        let second = read_u16(bytes, offset + 2)?;
        Ok(((((first & 0x7fff) as usize) << 16) | second as usize, 4))
    }
}

fn string_at(strings: &[String], index: u32) -> Option<&str> {
    if index == NO_INDEX {
        return None;
    }
    strings.get(index as usize).map(String::as_str)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StringPoolDetails {
    strings: Vec<String>,
    flags: u32,
    style_count: usize,
    style_offsets: Vec<u32>,
    style_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderChunkIndexes {
    android_namespace_index: u32,
    provider_element_index: u32,
    name_attr_index: u32,
    exported_attr_index: u32,
    authorities_attr_index: u32,
    init_order_attr_index: Option<u32>,
    provider_name_index: u32,
    provider_authorities_index: u32,
    exported: bool,
    init_order: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderAttributeChunk {
    resource_id: u32,
    namespace_index: u32,
    name_index: u32,
    raw_value_index: u32,
    value_type: u8,
    value_data: u32,
}

fn validate_provider(provider: &ManifestProvider) -> Result<(), AxmlError> {
    if provider.name.trim().is_empty() {
        return Err(AxmlError::Invalid("provider class name must not be empty"));
    }
    if provider.authorities.trim().is_empty() {
        return Err(AxmlError::Invalid("provider authority must not be empty"));
    }
    if provider.authorities.contains(';') {
        return Err(AxmlError::Invalid(
            "provider authority must contain exactly one authority",
        ));
    }
    if provider.name.contains('\0') || provider.authorities.contains('\0') {
        return Err(AxmlError::Invalid("provider values must not contain NUL"));
    }
    Ok(())
}

fn find_required_chunk_offset(
    bytes: &[u8],
    start: usize,
    end: usize,
    chunk_type: u16,
) -> Result<usize, AxmlError> {
    find_optional_chunk_offset(bytes, start, end, chunk_type)?
        .ok_or(AxmlError::Invalid("required binary XML chunk is missing"))
}

fn find_optional_chunk_offset(
    bytes: &[u8],
    start: usize,
    end: usize,
    chunk_type: u16,
) -> Result<Option<usize>, AxmlError> {
    let mut offset = start;
    while offset < end {
        let header = read_chunk_header(bytes, offset)?;
        let chunk_end = checked_chunk_end(bytes, offset, header.size)?;
        if chunk_end > end {
            return Err(AxmlError::Truncated("nested binary XML chunk"));
        }
        if header.chunk_type == chunk_type {
            return Ok(Some(offset));
        }
        offset = chunk_end;
    }
    Ok(None)
}

fn parse_string_pool_details(
    bytes: &[u8],
    offset: usize,
    header: &ChunkHeader,
) -> Result<StringPoolDetails, AxmlError> {
    if header.header_size < 28 {
        return Err(AxmlError::Invalid("string pool header is too small"));
    }
    if header.header_size as u32 > header.size {
        return Err(AxmlError::Invalid("string pool header exceeds chunk size"));
    }

    let strings = parse_string_pool(bytes, offset, header)?;
    let string_count = read_u32(bytes, offset + 8)? as usize;
    let style_count = read_u32(bytes, offset + 12)? as usize;
    let flags = read_u32(bytes, offset + 16)?;
    let styles_start = read_u32(bytes, offset + 24)? as usize;
    let chunk_end = checked_chunk_end(bytes, offset, header.size)?;
    let offsets_start = offset
        .checked_add(header.header_size as usize)
        .ok_or(AxmlError::Invalid("string offsets overflow"))?;
    let style_offsets_start = offsets_start
        .checked_add(
            string_count
                .checked_mul(4)
                .ok_or(AxmlError::Invalid("string offsets size overflow"))?,
        )
        .ok_or(AxmlError::Invalid("style offsets overflow"))?;
    require_len(
        bytes,
        offsets_start,
        string_count
            .checked_add(style_count)
            .and_then(|count| count.checked_mul(4))
            .ok_or(AxmlError::Invalid("string pool offsets size overflow"))?,
        "string pool offsets",
    )?;
    if style_offsets_start > chunk_end {
        return Err(AxmlError::Truncated("style offsets"));
    }

    let mut style_offsets = Vec::with_capacity(style_count);
    for index in 0..style_count {
        style_offsets.push(read_u32(bytes, style_offsets_start + index * 4)?);
    }

    let style_data = if style_count == 0 {
        Vec::new()
    } else {
        if styles_start == 0 {
            return Err(AxmlError::Invalid("styled string pool has no style data"));
        }
        let style_data_start = offset
            .checked_add(styles_start)
            .ok_or(AxmlError::Invalid("style data offset overflow"))?;
        if style_data_start > chunk_end {
            return Err(AxmlError::Truncated("style data"));
        }
        bytes[style_data_start..chunk_end].to_vec()
    };

    Ok(StringPoolDetails {
        strings,
        flags,
        style_count,
        style_offsets,
        style_data,
    })
}

fn parse_resource_map(
    bytes: &[u8],
    offset: usize,
    header: &ChunkHeader,
) -> Result<Vec<u32>, AxmlError> {
    if header.header_size < 8 {
        return Err(AxmlError::Invalid("resource map header is too small"));
    }
    if header.header_size as u32 > header.size {
        return Err(AxmlError::Invalid("resource map header exceeds chunk size"));
    }

    let chunk_end = checked_chunk_end(bytes, offset, header.size)?;
    let entries_start = offset
        .checked_add(header.header_size as usize)
        .ok_or(AxmlError::Invalid("resource map offset overflow"))?;
    let entries_len = chunk_end
        .checked_sub(entries_start)
        .ok_or(AxmlError::Invalid("resource map range overflow"))?;
    if entries_len % 4 != 0 {
        return Err(AxmlError::Invalid(
            "resource map size is not aligned to u32 entries",
        ));
    }

    let mut resource_ids = Vec::with_capacity(entries_len / 4);
    for entry_offset in (entries_start..chunk_end).step_by(4) {
        resource_ids.push(read_u32(bytes, entry_offset)?);
    }
    Ok(resource_ids)
}

fn find_application_end_offset(
    bytes: &[u8],
    start: usize,
    end: usize,
    strings: &[String],
) -> Result<usize, AxmlError> {
    let mut offset = start;
    let mut stack = Vec::new();
    while offset < end {
        let header = read_chunk_header(bytes, offset)?;
        let chunk_end = checked_chunk_end(bytes, offset, header.size)?;
        if chunk_end > end {
            return Err(AxmlError::Truncated("nested binary XML chunk"));
        }

        match header.chunk_type {
            RES_XML_START_ELEMENT_TYPE => {
                stack.push(xml_node_name(bytes, offset, strings)?.to_string());
            }
            RES_XML_END_ELEMENT_TYPE => {
                let element_name = xml_node_name(bytes, offset, strings)?;
                if element_name == "application" {
                    return Ok(offset);
                }
                stack.pop();
            }
            _ => {}
        }

        offset = chunk_end;
    }

    Err(AxmlError::Invalid(
        "AndroidManifest.xml is missing application element",
    ))
}

fn xml_node_name<'a>(
    bytes: &[u8],
    offset: usize,
    strings: &'a [String],
) -> Result<&'a str, AxmlError> {
    require_len(bytes, offset, 24, "XML node")?;
    string_at(strings, read_u32(bytes, offset + 20)?).ok_or(AxmlError::Invalid(
        "XML node name index does not reference the string pool",
    ))
}

fn get_or_push_string(strings: &mut Vec<String>, value: &str) -> Result<u32, AxmlError> {
    if let Some(index) = strings.iter().position(|existing| existing == value) {
        return to_u32(index, "string index");
    }

    strings.push(value.to_string());
    to_u32(strings.len() - 1, "string index")
}

fn build_string_pool(
    original: &StringPoolDetails,
    strings: &[String],
) -> Result<Vec<u8>, AxmlError> {
    let mut string_offsets = Vec::with_capacity(strings.len());
    let mut string_data = Vec::new();
    let use_utf8 = original.flags & UTF8_FLAG != 0;
    for value in strings {
        string_offsets.push(to_u32(string_data.len(), "string pool string offset")?);
        if use_utf8 {
            encode_utf8_string(&mut string_data, value)?;
        } else {
            encode_utf16_string(&mut string_data, value)?;
        }
    }
    align4(&mut string_data);

    let string_offsets_len = strings
        .len()
        .checked_mul(4)
        .ok_or(AxmlError::Invalid("string offsets size overflow"))?;
    let style_offsets_len = original
        .style_offsets
        .len()
        .checked_mul(4)
        .ok_or(AxmlError::Invalid("style offsets size overflow"))?;
    let strings_start = 28usize
        .checked_add(string_offsets_len)
        .and_then(|value| value.checked_add(style_offsets_len))
        .ok_or(AxmlError::Invalid("string pool header size overflow"))?;
    let styles_start = if original.style_count == 0 {
        0
    } else {
        strings_start
            .checked_add(string_data.len())
            .ok_or(AxmlError::Invalid("style data offset overflow"))?
    };
    let size = strings_start
        .checked_add(string_data.len())
        .and_then(|value| value.checked_add(original.style_data.len()))
        .ok_or(AxmlError::Invalid("string pool size overflow"))?;

    let mut output = Vec::with_capacity(size);
    write_u16(&mut output, RES_STRING_POOL_TYPE);
    write_u16(&mut output, 28);
    write_u32(&mut output, to_u32(size, "string pool size")?);
    write_u32(&mut output, to_u32(strings.len(), "string count")?);
    write_u32(&mut output, to_u32(original.style_count, "style count")?);
    write_u32(&mut output, original.flags & !SORTED_FLAG);
    write_u32(&mut output, to_u32(strings_start, "strings start")?);
    write_u32(&mut output, to_u32(styles_start, "styles start")?);
    for string_offset in string_offsets {
        write_u32(&mut output, string_offset);
    }
    for style_offset in &original.style_offsets {
        write_u32(&mut output, *style_offset);
    }
    output.extend_from_slice(&string_data);
    output.extend_from_slice(&original.style_data);
    debug_assert_eq!(output.len(), size);
    Ok(output)
}

fn encode_utf8_string(output: &mut Vec<u8>, value: &str) -> Result<(), AxmlError> {
    encode_length8(output, value.encode_utf16().count())?;
    encode_length8(output, value.len())?;
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    Ok(())
}

fn encode_utf16_string(output: &mut Vec<u8>, value: &str) -> Result<(), AxmlError> {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    encode_length16(output, utf16.len())?;
    for code_unit in utf16 {
        write_u16(output, code_unit);
    }
    write_u16(output, 0);
    Ok(())
}

fn encode_length8(output: &mut Vec<u8>, length: usize) -> Result<(), AxmlError> {
    if length <= 0x7f {
        output.push(length as u8);
    } else if length <= 0x7fff {
        output.push(((length >> 8) as u8) | 0x80);
        output.push((length & 0xff) as u8);
    } else {
        return Err(AxmlError::Invalid("UTF-8 string length is too large"));
    }
    Ok(())
}

fn encode_length16(output: &mut Vec<u8>, length: usize) -> Result<(), AxmlError> {
    if length <= 0x7fff {
        write_u16(output, length as u16);
    } else if length <= 0x7fff_ffff {
        write_u16(output, ((length >> 16) as u16) | 0x8000);
        write_u16(output, (length & 0xffff) as u16);
    } else {
        return Err(AxmlError::Invalid("UTF-16 string length is too large"));
    }
    Ok(())
}

fn build_resource_map(resource_ids: &[u32]) -> Result<Vec<u8>, AxmlError> {
    let size = 8usize
        .checked_add(
            resource_ids
                .len()
                .checked_mul(4)
                .ok_or(AxmlError::Invalid("resource map size overflow"))?,
        )
        .ok_or(AxmlError::Invalid("resource map size overflow"))?;
    let mut output = Vec::with_capacity(size);
    write_u16(&mut output, RES_XML_RESOURCE_MAP_TYPE);
    write_u16(&mut output, 8);
    write_u32(&mut output, to_u32(size, "resource map size")?);
    for resource_id in resource_ids {
        write_u32(&mut output, *resource_id);
    }
    Ok(output)
}

fn build_provider_chunks(indexes: ProviderChunkIndexes) -> Result<Vec<u8>, AxmlError> {
    let mut attributes = vec![
        ProviderAttributeChunk {
            resource_id: ANDROID_ATTR_NAME,
            namespace_index: indexes.android_namespace_index,
            name_index: indexes.name_attr_index,
            raw_value_index: indexes.provider_name_index,
            value_type: TYPE_STRING,
            value_data: indexes.provider_name_index,
        },
        ProviderAttributeChunk {
            resource_id: ANDROID_ATTR_EXPORTED,
            namespace_index: indexes.android_namespace_index,
            name_index: indexes.exported_attr_index,
            raw_value_index: NO_INDEX,
            value_type: TYPE_INT_BOOLEAN,
            value_data: if indexes.exported { u32::MAX } else { 0 },
        },
        ProviderAttributeChunk {
            resource_id: ANDROID_ATTR_AUTHORITIES,
            namespace_index: indexes.android_namespace_index,
            name_index: indexes.authorities_attr_index,
            raw_value_index: indexes.provider_authorities_index,
            value_type: TYPE_STRING,
            value_data: indexes.provider_authorities_index,
        },
    ];
    if let (Some(name_index), Some(init_order)) =
        (indexes.init_order_attr_index, indexes.init_order)
    {
        attributes.push(ProviderAttributeChunk {
            resource_id: ANDROID_ATTR_INIT_ORDER,
            namespace_index: indexes.android_namespace_index,
            name_index,
            raw_value_index: NO_INDEX,
            value_type: TYPE_INT_DEC,
            value_data: init_order as u32,
        });
    }
    attributes.sort_by_key(|attribute| (attribute.resource_id, attribute.name_index));

    let start_size = 36usize
        .checked_add(
            attributes
                .len()
                .checked_mul(20)
                .ok_or(AxmlError::Invalid("provider attribute size overflow"))?,
        )
        .ok_or(AxmlError::Invalid("provider chunk size overflow"))?;
    let mut output = Vec::with_capacity(start_size + 24);
    write_u16(&mut output, RES_XML_START_ELEMENT_TYPE);
    write_u16(&mut output, 16);
    write_u32(
        &mut output,
        to_u32(start_size, "provider start chunk size")?,
    );
    write_u32(&mut output, 0);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, indexes.provider_element_index);
    write_u16(&mut output, 20);
    write_u16(&mut output, 20);
    write_u16(
        &mut output,
        to_u16(attributes.len(), "provider attribute count")?,
    );
    write_u16(&mut output, 0);
    write_u16(&mut output, 0);
    write_u16(&mut output, 0);

    for attribute in attributes {
        write_u32(&mut output, attribute.namespace_index);
        write_u32(&mut output, attribute.name_index);
        write_u32(&mut output, attribute.raw_value_index);
        write_u16(&mut output, 8);
        output.push(0);
        output.push(attribute.value_type);
        write_u32(&mut output, attribute.value_data);
    }

    write_u16(&mut output, RES_XML_END_ELEMENT_TYPE);
    write_u16(&mut output, 16);
    write_u32(&mut output, 24);
    write_u32(&mut output, 0);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, indexes.provider_element_index);
    Ok(output)
}

fn align4(output: &mut Vec<u8>) {
    while output.len() % 4 != 0 {
        output.push(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChunkHeader {
    chunk_type: u16,
    header_size: u16,
    size: u32,
}

fn read_chunk_header(bytes: &[u8], offset: usize) -> Result<ChunkHeader, AxmlError> {
    require_len(bytes, offset, 8, "chunk header")?;
    Ok(ChunkHeader {
        chunk_type: read_u16(bytes, offset)?,
        header_size: read_u16(bytes, offset + 2)?,
        size: read_u32(bytes, offset + 4)?,
    })
}

fn checked_chunk_end(bytes: &[u8], offset: usize, size: u32) -> Result<usize, AxmlError> {
    let end = offset
        .checked_add(size as usize)
        .ok_or(AxmlError::Invalid("chunk size overflow"))?;
    if end > bytes.len() {
        return Err(AxmlError::Truncated("chunk"));
    }
    if size < 8 {
        return Err(AxmlError::Invalid("chunk size is too small"));
    }
    Ok(end)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, AxmlError> {
    require_len(bytes, offset, 1, "u8")?;
    Ok(bytes[offset])
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AxmlError> {
    require_len(bytes, offset, 2, "u16")?;
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AxmlError> {
    require_len(bytes, offset, 4, "u32")?;
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32_at(output: &mut [u8], offset: usize, value: u32) -> Result<(), AxmlError> {
    require_len(output, offset, 4, "u32 write")?;
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn to_u16(value: usize, label: &'static str) -> Result<u16, AxmlError> {
    u16::try_from(value).map_err(|_| AxmlError::Invalid(label))
}

fn to_u32(value: usize, label: &'static str) -> Result<u32, AxmlError> {
    u32::try_from(value).map_err(|_| AxmlError::Invalid(label))
}

fn require_len(
    bytes: &[u8],
    offset: usize,
    required_len: usize,
    label: &'static str,
) -> Result<(), AxmlError> {
    let end = offset
        .checked_add(required_len)
        .ok_or(AxmlError::Invalid("offset overflow"))?;
    if end > bytes.len() {
        Err(AxmlError::Truncated(label))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_uses_first_eight_build_id_characters() {
        assert_eq!(
            bootstrap_provider_authority(
                "com.example.mobile",
                "a91f30c2-0000-0000-0000-000000000000"
            ),
            "com.example.mobile.rasp.a91f30c2"
        );
    }

    #[test]
    fn injects_bootstrap_provider_before_application_end() {
        let manifest = minimal_manifest("com.example.mobile");
        let provider = test_provider();

        let updated = inject_manifest_provider(&manifest, &provider).expect("inject provider");
        let parsed = parse_manifest(&updated).expect("parse updated manifest");

        assert_eq!(parsed.package_name.as_deref(), Some("com.example.mobile"));
        assert_eq!(
            parsed.providers,
            vec![ProviderDeclaration {
                name: Some(provider.name),
                authorities: Some(provider.authorities),
                exported: Some(false),
            }]
        );
    }

    #[test]
    fn injects_resource_ids_for_provider_attributes() {
        let manifest = minimal_manifest("com.example.mobile");
        let provider = test_provider();

        let updated = inject_manifest_provider(&manifest, &provider).expect("inject provider");
        let (strings, resource_ids) = string_pool_and_resource_map(&updated);

        assert_eq!(
            resource_ids[string_index(&strings, "name")],
            ANDROID_ATTR_NAME
        );
        assert_eq!(
            resource_ids[string_index(&strings, "exported")],
            ANDROID_ATTR_EXPORTED
        );
        assert_eq!(
            resource_ids[string_index(&strings, "authorities")],
            ANDROID_ATTR_AUTHORITIES
        );
        assert_eq!(
            resource_ids[string_index(&strings, "initOrder")],
            ANDROID_ATTR_INIT_ORDER
        );
    }

    #[test]
    fn rejects_duplicate_bootstrap_provider() {
        let manifest = minimal_manifest("com.example.mobile");
        let provider = test_provider();
        let updated = inject_manifest_provider(&manifest, &provider).expect("inject provider");

        let error = inject_manifest_provider(&updated, &provider).expect_err("duplicate fails");

        assert!(error
            .to_string()
            .contains("bootstrap provider already exists"));
    }

    #[derive(Debug, Clone, Copy)]
    struct TestAttribute {
        namespace_index: u32,
        name_index: u32,
        raw_value_index: u32,
        value_type: u8,
        value_data: u32,
    }

    fn test_provider() -> ManifestProvider {
        ManifestProvider {
            name: "com.rasp.runtime.bootstrap.RaspInitProvider".to_string(),
            authorities: "com.example.mobile.rasp.a91f30c2".to_string(),
            exported: false,
            init_order: Some(1000),
        }
    }

    fn minimal_manifest(package_name: &str) -> Vec<u8> {
        let strings = vec![
            ANDROID_NAMESPACE_URI.to_string(),
            "manifest".to_string(),
            "application".to_string(),
            "package".to_string(),
            package_name.to_string(),
        ];
        let empty_pool = StringPoolDetails {
            strings: Vec::new(),
            flags: UTF8_FLAG,
            style_count: 0,
            style_offsets: Vec::new(),
            style_data: Vec::new(),
        };
        let string_pool = build_string_pool(&empty_pool, &strings).expect("build string pool");
        let manifest_index = string_index(&strings, "manifest") as u32;
        let application_index = string_index(&strings, "application") as u32;
        let package_index = string_index(&strings, "package") as u32;
        let package_value_index = string_index(&strings, package_name) as u32;

        let mut body = Vec::new();
        body.extend_from_slice(&string_pool);
        body.extend_from_slice(&start_element(
            manifest_index,
            &[TestAttribute {
                namespace_index: NO_INDEX,
                name_index: package_index,
                raw_value_index: package_value_index,
                value_type: TYPE_STRING,
                value_data: package_value_index,
            }],
        ));
        body.extend_from_slice(&start_element(application_index, &[]));
        body.extend_from_slice(&end_element(application_index));
        body.extend_from_slice(&end_element(manifest_index));

        let mut output = Vec::new();
        write_u16(&mut output, RES_XML_TYPE);
        write_u16(&mut output, 8);
        write_u32(
            &mut output,
            to_u32(8 + body.len(), "test XML size").unwrap(),
        );
        output.extend_from_slice(&body);
        output
    }

    fn start_element(name_index: u32, attributes: &[TestAttribute]) -> Vec<u8> {
        let size = 36 + attributes.len() * 20;
        let mut output = Vec::new();
        write_u16(&mut output, RES_XML_START_ELEMENT_TYPE);
        write_u16(&mut output, 16);
        write_u32(&mut output, size as u32);
        write_u32(&mut output, 0);
        write_u32(&mut output, NO_INDEX);
        write_u32(&mut output, NO_INDEX);
        write_u32(&mut output, name_index);
        write_u16(&mut output, 20);
        write_u16(&mut output, 20);
        write_u16(&mut output, attributes.len() as u16);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        for attribute in attributes {
            write_u32(&mut output, attribute.namespace_index);
            write_u32(&mut output, attribute.name_index);
            write_u32(&mut output, attribute.raw_value_index);
            write_u16(&mut output, 8);
            output.push(0);
            output.push(attribute.value_type);
            write_u32(&mut output, attribute.value_data);
        }
        output
    }

    fn end_element(name_index: u32) -> Vec<u8> {
        let mut output = Vec::new();
        write_u16(&mut output, RES_XML_END_ELEMENT_TYPE);
        write_u16(&mut output, 16);
        write_u32(&mut output, 24);
        write_u32(&mut output, 0);
        write_u32(&mut output, NO_INDEX);
        write_u32(&mut output, NO_INDEX);
        write_u32(&mut output, name_index);
        output
    }

    fn string_pool_and_resource_map(bytes: &[u8]) -> (Vec<String>, Vec<u32>) {
        let root = read_chunk_header(bytes, 0).expect("root header");
        let root_end = checked_chunk_end(bytes, 0, root.size).expect("root end");
        let string_pool_offset = find_required_chunk_offset(
            bytes,
            root.header_size as usize,
            root_end,
            RES_STRING_POOL_TYPE,
        )
        .expect("string pool offset");
        let string_pool_header =
            read_chunk_header(bytes, string_pool_offset).expect("string pool header");
        let string_pool_end = checked_chunk_end(bytes, string_pool_offset, string_pool_header.size)
            .expect("string pool end");
        let strings = parse_string_pool_details(bytes, string_pool_offset, &string_pool_header)
            .expect("string pool")
            .strings;
        let resource_map_offset =
            find_required_chunk_offset(bytes, string_pool_end, root_end, RES_XML_RESOURCE_MAP_TYPE)
                .expect("resource map offset");
        let resource_map_header =
            read_chunk_header(bytes, resource_map_offset).expect("resource map header");
        let resource_ids = parse_resource_map(bytes, resource_map_offset, &resource_map_header)
            .expect("resource map");
        (strings, resource_ids)
    }

    fn string_index(strings: &[String], value: &str) -> usize {
        strings
            .iter()
            .position(|existing| existing == value)
            .expect("string exists")
    }
}
