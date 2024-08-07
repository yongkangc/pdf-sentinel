use flate2::read::ZlibDecoder;
use lopdf::{Dictionary, Document, Object, Stream};
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read};

#[derive(Deserialize)]
struct Config {
    file_size_threshold: u64,
    suspicious_patterns: Vec<String>,
    suspicious_metadata_patterns: Vec<String>,
}

#[derive(Default)]
struct AnalysisResult {
    has_javascript: bool,
    has_auto_action: bool,
    has_obj_stm: bool,
    suspicious_names: Vec<String>,
    hidden_content: bool,
    large_file_size: bool,
    suspicious_metadata: bool,
    unusual_objects: Vec<String>,
    object_statistics: ObjectStatistics,
    severity_score: u32,
    javascript_objects: Vec<JavaScriptObject>,
}

#[derive(Default)]
struct ObjectStatistics {
    total_objects: usize,
    stream_objects: usize,
    js_objects: usize,
    obj_stm_objects: usize,
}

struct JavaScriptObject {
    id: u32,
    content: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();
    let file = File::open("sample.pdf")?;
    let reader = BufReader::new(file);
    let doc = Document::load_from(reader)?;

    let result = analyze_pdf(&doc, &config);

    print_analysis_result(&result);

    Ok(())
}

fn load_config() -> Config {
    // Load from a file or use default values
    Config {
        file_size_threshold: 10 * 1024 * 1024,
        suspicious_patterns: vec![
            r"(?i)eval".to_string(),
            r"(?i)exec".to_string(),
            r"(?i)spawn".to_string(),
            r"(?i)shell".to_string(),
        ],
        suspicious_metadata_patterns: vec![r"(?i)(adobe|microsoft|office)".to_string()],
    }
}

fn analyze_pdf(doc: &Document, config: &Config) -> AnalysisResult {
    let mut result = AnalysisResult::default();

    result.has_javascript = check_for_javascript(doc);
    result.javascript_objects = find_javascript_objects(doc);
    result.has_auto_action = check_for_auto_action(doc);
    result.has_obj_stm = check_for_obj_stm(doc);
    result.suspicious_names = check_for_suspicious_names(doc, config);
    result.hidden_content = check_for_hidden_content(doc);
    result.large_file_size = check_file_size(doc, config);
    result.suspicious_metadata = check_metadata(doc, config);
    result.unusual_objects = check_for_unusual_objects(doc);
    result.object_statistics = calculate_object_statistics(doc);

    analyze_streams(doc, config, &mut result);

    result.severity_score = calculate_severity_score(&result);

    result
}

fn check_for_javascript(doc: &Document) -> bool {
    doc.objects.iter().any(|(_, object)| {
        if let Ok(dict) = object.as_dict() {
            dict.has(b"JS")
                || dict.has(b"JavaScript")
                || dict
                    .get(b"S")
                    .map_or(false, |s| s.as_name().map_or(false, |n| n == b"JavaScript"))
        } else {
            false
        }
    })
}

fn find_javascript_objects(doc: &Document) -> Vec<JavaScriptObject> {
    let mut js_objects = Vec::new();

    for (id, object) in doc.objects.iter() {
        if let Ok(dict) = object.as_dict() {
            if dict.has(b"JS") || dict.has(b"JavaScript") {
                if let Some(stream) = object.as_stream().ok() {
                    if let Ok(filter) = stream.filter() {
                        if filter == "FlateDecode" {
                            let mut decoder = ZlibDecoder::new(&stream.content[..]);
                            let mut decompressed = Vec::new();
                            if decoder.read_to_end(&mut decompressed).is_ok() {
                                if let Ok(content) = str::from_utf8(&decompressed) {
                                    js_objects.push(JavaScriptObject {
                                        id: id.0,
                                        content: content.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    js_objects
}

fn check_for_auto_action(doc: &Document) -> bool {
    doc.objects.iter().any(|(_, object)| {
        if let Ok(dict) = object.as_dict() {
            dict.has(b"AA") || dict.has(b"OpenAction")
        } else {
            false
        }
    })
}

fn check_for_obj_stm(doc: &Document) -> bool {
    doc.objects.iter().any(|(_, object)| {
        if let Ok(dict) = object.as_dict() {
            dict.has(b"ObjStm")
        } else {
            false
        }
    })
}

fn check_for_suspicious_names(doc: &Document, config: &Config) -> Vec<String> {
    let re = Regex::new(&config.suspicious_patterns.join("|")).unwrap();

    doc.objects
        .iter()
        .filter_map(|(_, obj)| match obj {
            Object::Name(name) | Object::String(name) => {
                let name_str = String::from_utf8_lossy(name).to_string();
                if re.is_match(&name_str) {
                    Some(name_str)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect()
}

fn check_for_hidden_content(doc: &Document) -> bool {
    doc.objects.iter().any(|(_, obj)| {
        if let Ok(dict) = obj.as_dict() {
            dict.has(b"OCG") || dict.has(b"OCGs")
        } else {
            false
        }
    })
}

fn check_file_size(doc: &Document, config: &Config) -> bool {
    doc.size() > config.file_size_threshold
}

fn check_metadata(doc: &Document, config: &Config) -> bool {
    let re = Regex::new(&config.suspicious_metadata_patterns.join("|")).unwrap();

    if let Some(info) = doc.trailer.get(b"Info") {
        if let Ok(info_dict) = info.as_dict() {
            return info_dict.iter().any(|(_, value)| {
                if let Ok(str_value) = value.as_string() {
                    let value_str = String::from_utf8_lossy(str_value);
                    !re.is_match(&value_str)
                } else {
                    false
                }
            });
        }
    }
    false
}

fn check_for_unusual_objects(doc: &Document) -> Vec<String> {
    let common_types = [
        b"Catalog",
        b"Pages",
        b"Page",
        b"Font",
        b"XObject",
        b"Metadata",
    ];
    doc.objects
        .iter()
        .filter_map(|(_, obj)| {
            if let Ok(dict) = obj.as_dict() {
                if let Some(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name() {
                        if !common_types.contains(&type_name) {
                            return Some(String::from_utf8_lossy(type_name).to_string());
                        }
                    }
                }
            }
            None
        })
        .collect()
}

fn calculate_object_statistics(doc: &Document) -> ObjectStatistics {
    let mut stats = ObjectStatistics::default();
    stats.total_objects = doc.objects.len();
    for (_, obj) in doc.objects.iter() {
        if obj.as_stream().is_ok() {
            stats.stream_objects += 1;
        }
        if let Ok(dict) = obj.as_dict() {
            if dict.has(b"JS") || dict.has(b"JavaScript") {
                stats.js_objects += 1;
            }
            if dict.has(b"ObjStm") {
                stats.obj_stm_objects += 1;
            }
        }
    }
    stats
}

fn analyze_streams(doc: &Document, config: &Config, result: &mut AnalysisResult) {
    let re = Regex::new(&config.suspicious_patterns.join("|")).unwrap();

    for (_, object) in doc.objects.iter() {
        if let Ok(stream) = object.as_stream() {
            if let Ok(filter) = stream.filter() {
                if filter == "FlateDecode" {
                    let mut decoder = ZlibDecoder::new(&stream.content[..]);
                    let mut decompressed = Vec::new();
                    if decoder.read_to_end(&mut decompressed).is_ok() {
                        let content = String::from_utf8_lossy(&decompressed);
                        if re.is_match(&content) {
                            result
                                .suspicious_names
                                .push("Suspicious content in stream".to_string());
                        }
                    }
                }
            }
        }
    }
}

fn calculate_severity_score(result: &AnalysisResult) -> u32 {
    let mut score = 0;
    if result.has_javascript {
        score += 3;
    }
    if result.has_auto_action {
        score += 2;
    }
    if result.has_obj_stm {
        score += 2;
    }
    score += result.suspicious_names.len() as u32;
    if result.hidden_content {
        score += 2;
    }
    if result.large_file_size {
        score += 1;
    }
    if result.suspicious_metadata {
        score += 2;
    }
    score += result.unusual_objects.len() as u32;
    score += (result.object_statistics.js_objects * 2) as u32;
    score += result.object_statistics.obj_stm_objects as u32;
    score
}

fn print_analysis_result(result: &AnalysisResult) {
    println!("PDF Analysis Result:");
    println!("- Contains JavaScript: {}", result.has_javascript);
    println!("- Contains Auto Action: {}", result.has_auto_action);
    println!("- Contains Object Streams: {}", result.has_obj_stm);
    println!("- Suspicious names found: {:?}", result.suspicious_names);
    println!("- Contains hidden content: {}", result.hidden_content);
    println!("- Large file size: {}", result.large_file_size);
    println!("- Suspicious metadata: {}", result.suspicious_metadata);
    println!("- Unusual objects: {:?}", result.unusual_objects);
    println!("- Object Statistics:");
    println!("JavaScript Objects:");
    for js_obj in &result.javascript_objects {
        println!("Object ID: {}", js_obj.id);
        println!("JavaScript Content:\n{}", js_obj.content);
        println!("--------------------");
    }
    println!(
        "  Total Objects: {}",
        result.object_statistics.total_objects
    );
    println!(
        "  Stream Objects: {}",
        result.object_statistics.stream_objects
    );
    println!(
        "  JavaScript Objects: {}",
        result.object_statistics.js_objects
    );
    println!(
        "  Object Stream Objects: {}",
        result.object_statistics.obj_stm_objects
    );
    println!("- Severity Score: {}", result.severity_score);

    let severity = match result.severity_score {
        0..=2 => "Low",
        3..=5 => "Medium",
        6..=10 => "High",
        _ => "Critical",
    };

    println!(
        "\nOverall assessment: {} (Severity: {})",
        if result.severity_score > 0 {
            "Potentially malicious"
        } else {
            "Likely benign"
        },
        severity
    );
}

fn analyze_multiple_pdfs(files: Vec<String>, config: &Config) -> Vec<(String, AnalysisResult)> {
    files
        .par_iter()
        .map(|file| {
            let doc = Document::load(file).unwrap();
            let result = analyze_pdf(&doc, config);
            (file.clone(), result)
        })
        .collect()
}
