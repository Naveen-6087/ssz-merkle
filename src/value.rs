use std::fmt::Write;

/// Type-erased view of an SSZ value, following the canonical JSON mapping:
/// integers as decimal strings, byte vectors/lists and bitfields as `0x` hex
/// of their SSZ bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(String),
    Bool(bool),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Container(Vec<(&'static str, Value)>),
}

impl Value {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Value::Uint(n) => write!(out, "\"{n}\"").unwrap(),
            Value::Bool(b) => write!(out, "{b}").unwrap(),
            Value::Bytes(bytes) => {
                out.push_str("\"0x");
                for b in bytes {
                    write!(out, "{b:02x}").unwrap();
                }
                out.push('"');
            }
            Value::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Container(fields) => {
                out.push('{');
                for (i, (name, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write!(out, "\"{name}\":").unwrap();
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mapping() {
        let v = Value::Container(vec![
            ("slot", Value::Uint("18446744073709551615".into())),
            ("ok", Value::Bool(true)),
            ("root", Value::Bytes(vec![0xab, 0x01])),
            ("items", Value::List(vec![Value::Uint("1".into()), Value::Uint("2".into())])),
        ]);
        assert_eq!(
            v.to_json(),
            r#"{"slot":"18446744073709551615","ok":true,"root":"0xab01","items":["1","2"]}"#
        );
    }
}
