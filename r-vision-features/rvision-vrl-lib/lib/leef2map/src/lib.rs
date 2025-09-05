// Inspired by "https://docs.serde.rs/serde_json/"
// Starting point for universal parser and structure detector in serde environment (but not with serde yet -_-)

// FIXME: No escaped symbols in text readers! Delimiter and special symbols must not occur in headers, keys and values!
// FIXME: Other specifications may specify cases for escaping special characters.
mod nom_impl;
use bytes::Bytes;
use std::collections::BTreeMap;
use syslog::SyslogData;

pub use nom_impl::{parse_leef, parse_leef_map};

#[allow(clippy::zero_prefixed_literal)]
static HEX: [u8; 256] = {
    const __: u8 = 255; // not a hex digit
    [
        //   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 0
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 1
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 2
        00, 01, 02, 03, 04, 05, 06, 07, 08, 09, __, __, __, __, __, __, // 3
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 4
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 5
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 6
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 7
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 8
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 9
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // A
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // B
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // C
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // D
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // E
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // F
    ]
};

fn decode_hex_digit(val: u8) -> Option<u8> {
    let n = HEX[val as usize];
    if n == 255 {
        None
    } else {
        Some(n)
    }
}

// Syslog headers:
// * ahost
// * at
// * syslog_facility
// * syslog_priority
// * syslog_severity
// LEEF headers:
// * leefVersion
// * deviceVendor
// * productName
// * productVersion
// * eventName
// * leefDelimiter

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeefLine<V = Bytes> {
    pub syslog: SyslogData,
    pub leef_components: BTreeMap<String, V>,
}

impl<V> Default for LeefLine<V> {
    fn default() -> Self {
        Self {
            syslog: SyslogData::default(),
            leef_components: BTreeMap::new(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Separator {
    Single(u8),
    Double(u8, u8),
}

impl From<u8> for Separator {
    fn from(b: u8) -> Self {
        Separator::Single(b)
    }
}

#[cfg(test)]
mod leef_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn deserialize(data: &[u8]) -> LeefLine {
        parse_leef(data).unwrap().1
    }

    #[test]
    fn basic_leef1() {
        let data = b"<13>1 2019-01-18T11:07:53.520Z 192.168.1.1 LEEF:1.0|Microsoft|MSExchange|2007|7732|ABC=123\tQWE=iop";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("2019-01-18T11:07:53.520Z".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "iop".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2() {
        let data = b"<13>1 2019-01-18T11:07:53.520Z 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC=123^QWE=io\t|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("2019-01-18T11:07:53.520Z".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io\t|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_trim() {
        let data = b"<13>1 2019-01-18T11:07:53.520Z 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC  =  123 ^ QWE  = io\t|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("2019-01-18T11:07:53.520Z".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io\t|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }
    #[test]
    fn basic_leef2_hex_separator() {
        let data = b"<13>1 2019-01-18T11:07:53.520Z 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|x5E|ABC=123^QWE=io\t|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("2019-01-18T11:07:53.520Z".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io\t|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }
    #[test]
    fn basic_leef2_syslog_rfc_3164() {
        let data = b"<13>Jan  8 11:07:53 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC=123^QWE=io|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("Jan 8 11:07:53".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }
    #[test]
    fn basic_leef2_unicode_separator() {
        let data = "<13>Jan 18 11:07:53 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|xC2A9|ABC=123©QWE=io|p".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: Some("1".into()),
                    syslog_priority: Some("13".into()),
                    syslog_severity: Some("5".into()),
                    at: Some("Jan 18 11:07:53".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_syslog_rfc_3164_without_pri() {
        let data = b"Jan 18 11:07:53 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC=123^QWE=io|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: Some("Jan 18 11:07:53".into()),
                    ahost: Some("192.168.1.1".into())
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_without_syslog() {
        let data = b"  LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC=123^QWE=io|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_malformed_syslog() {
        let data = b" <qwe> asd eqw LEEF:2.0|Microsoft|MSExchange|2007|7732|^|ABC=123^QWE=io|p";

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "123".into());
                    map.insert("QWE".into(), "io|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_double_separator() {
        let data =
            "  LEEF:2.0|Microsoft|MSExchange|2007|7732|x0d0A|ABC=1\r23\r\nQWE=io\n|p".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("ABC".into(), "1\r23".into());
                    map.insert("QWE".into(), "io\n|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_malformed_separator_becomes_part_of_key() {
        let data =
            "  LEEF:2.0|Microsoft|MSExchange|2007|7732|abcd|ABC=1\r23\tQWE=io\n|p".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("abcd|ABC".into(), "1\r23".into());
                    map.insert("QWE".into(), "io\n|p".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_only_header() {
        let data = "LEEF:2.0|Microsoft|MSExchange|2007|7732|^|".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn basic_leef2_only_header_no_sep() {
        let data = "LEEF:2.0|Microsoft|MSExchange|2007|7732|".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    #[should_panic]
    fn basic_leef2_only_header_and_malformed_body() {
        let data = "LEEF:2.0|Microsoft|MSExchange|2007|7732|^|asdasd".as_bytes();

        let _leef = deserialize(data);
    }

    #[test]
    fn big_leef2() {
        let data = "LEEF:2.0|Microsoft|MSExchange|2007|7732|x09|AgentDevice=WindowsLog\tAgentLogFile=Security\tPluginVersion=7.2.9.105\tSource=Microsoft-Windows-Security-Auditing\tComputer=dc04.lab2012.local\tOriginatingComputer=10.99.101.128\tUser=\tDomain=\tEventID=4624\tEventIDCode=4624\tEventType=8\tEventCategory=12544\tRecordNumber=11103971\tTimeGenerated=1610705793\tTimeWritten=1610705793\tLevel=Log Always\tKeywords=Audit Success\tTask=SE_ADT_LOGON_LOGON\tOpcode=Info\tMessage=Вход с учетной записью выполнен успешно.  Субъект:  ИД безопасности:  NULL SID  Имя учетной записи:  -  Домен учетной записи:  -  Код входа:  0x0  Тип входа:   3  Уровень олицетворения:  Делегирование  Новый вход:  ИД безопасности:  NT AUTHORITY\\СИСТЕМА  Имя учетной записи:  DC04$  Домен учетной записи:  LAB2012  Код входа:  0x1E6112B9  GUID входа:  {06457096-03A4-55FB-28EA-9882B565E681}  Сведения о процессе:  Идентификатор процесса:  0x0  Имя процесса:  -  Сведения о сети:  Имя рабочей станции: -  Сетевой адрес источника: fe80::7830:1b00:4e5f:1300  Порт источника:  51755  Сведения о проверке подлинности:  Процесс входа:  Kerberos  Пакет проверки подлинности: Kerberos  Промежуточные службы: -  Имя пакета (только NTLM): -  Длина ключа:  0  Данное событие возникает при создании сеанса входа. Оно создается в системе, вход в которую выполнен.  Поля \"Субъект\" указывают на учетную запись локальной системы, запросившую вход. Обычно это служба, например, служба \"Сервер\", или локальный процесс, такой как Winlogon.exe или Services.exe.  В поле \"Тип входа\" указан тип выполненного входа. Самыми распространенными являются типы 2 (интерактивный) и 3 (сетевой).  Поля \"Новый вход\" указывают на учетную запись, для которой создан новый сеанс входа, то есть на учетную запись, с которой выполнен вход.  В полях, которые относятся к сети, указан источник запроса на удаленный вход. Имя рабочей станции доступно не всегда, и в некоторых случаях это поле может оставаться незаполненным.  Поле \"Уровень олицетворения\" задает допустимую степень олицетворения для процессов в данном сеансе входа в систему.  Поля сведений о проверке подлинности содержат подробные данные о конкретном запросе на вход.  - GUID входа - это уникальный идентификатор, который позволяет сопоставить данное событие с событием KDC.  - В поле \"Промежуточные службы\" указано, какие промежуточные службы участвовали в данном запросе на вход.  - Поле \"Имя пакета\" указывает на подпротокол, использованный с протоколами NTLM.  - Поле \"Длина ключа\" содержит длину созданного ключа сеанса. Это поле может иметь значение \"0\", если ключ сеанса не запрашивался.\n".as_bytes();

        let leef = deserialize(data);

        assert_eq!(
            leef,
            LeefLine {
                syslog: SyslogData {
                    syslog_facility: None,
                    syslog_priority: None,
                    syslog_severity: None,
                    at: None,
                    ahost: None
                },
                leef_components: {
                    let mut map = BTreeMap::new();
                    map.insert("AgentDevice".into(), "WindowsLog".into());
                    map.insert("AgentLogFile".into(), "Security".into());
                    map.insert("Computer".into(), "dc04.lab2012.local".into());
                    map.insert("Domain".into(), "".into());
                    map.insert("EventCategory".into(), "12544".into());
                    map.insert("EventID".into(), "4624".into());
                    map.insert("EventIDCode".into(), "4624".into());
                    map.insert("EventType".into(), "8".into());
                    map.insert("Keywords".into(), "Audit Success".into());
                    map.insert("Level".into(), "Log Always".into());
                    map.insert("Message".into(), "Вход с учетной записью выполнен успешно.  Субъект:  ИД безопасности:  NULL SID  Имя учетной записи:  -  Домен учетной записи:  -  Код входа:  0x0  Тип входа:   3  Уровень олицетворения:  Делегирование  Новый вход:  ИД безопасности:  NT AUTHORITY\\СИСТЕМА  Имя учетной записи:  DC04$  Домен учетной записи:  LAB2012  Код входа:  0x1E6112B9  GUID входа:  {06457096-03A4-55FB-28EA-9882B565E681}  Сведения о процессе:  Идентификатор процесса:  0x0  Имя процесса:  -  Сведения о сети:  Имя рабочей станции: -  Сетевой адрес источника: fe80::7830:1b00:4e5f:1300  Порт источника:  51755  Сведения о проверке подлинности:  Процесс входа:  Kerberos  Пакет проверки подлинности: Kerberos  Промежуточные службы: -  Имя пакета (только NTLM): -  Длина ключа:  0  Данное событие возникает при создании сеанса входа. Оно создается в системе, вход в которую выполнен.  Поля \"Субъект\" указывают на учетную запись локальной системы, запросившую вход. Обычно это служба, например, служба \"Сервер\", или локальный процесс, такой как Winlogon.exe или Services.exe.  В поле \"Тип входа\" указан тип выполненного входа. Самыми распространенными являются типы 2 (интерактивный) и 3 (сетевой).  Поля \"Новый вход\" указывают на учетную запись, для которой создан новый сеанс входа, то есть на учетную запись, с которой выполнен вход.  В полях, которые относятся к сети, указан источник запроса на удаленный вход. Имя рабочей станции доступно не всегда, и в некоторых случаях это поле может оставаться незаполненным.  Поле \"Уровень олицетворения\" задает допустимую степень олицетворения для процессов в данном сеансе входа в систему.  Поля сведений о проверке подлинности содержат подробные данные о конкретном запросе на вход.  - GUID входа - это уникальный идентификатор, который позволяет сопоставить данное событие с событием KDC.  - В поле \"Промежуточные службы\" указано, какие промежуточные службы участвовали в данном запросе на вход.  - Поле \"Имя пакета\" указывает на подпротокол, использованный с протоколами NTLM.  - Поле \"Длина ключа\" содержит длину созданного ключа сеанса. Это поле может иметь значение \"0\", если ключ сеанса не запрашивался.".into());
                    map.insert("Opcode".into(), "Info".into());
                    map.insert("OriginatingComputer".into(), "10.99.101.128".into());
                    map.insert("PluginVersion".into(), "7.2.9.105".into());
                    map.insert("RecordNumber".into(), "11103971".into());
                    map.insert(
                        "Source".into(),
                        "Microsoft-Windows-Security-Auditing".into(),
                    );
                    map.insert("Task".into(), "SE_ADT_LOGON_LOGON".into());
                    map.insert("TimeGenerated".into(), "1610705793".into());
                    map.insert("TimeWritten".into(), "1610705793".into());
                    map.insert("User".into(), "".into());
                    map.insert("deviceVendor".into(), "Microsoft".into());
                    map.insert("eventName".into(), "7732".into());
                    map.insert("productName".into(), "MSExchange".into());
                    map.insert("productVersion".into(), "2007".into());
                    map
                }
            }
        );
    }

    #[test]
    fn invalid_utf8_key() {
        let data =
            b"Jan 18 11:07:53 192.168.1.1 LEEF:2.0|Microsoft|MSExchange|2007|7732|^|A\xFFBC=123";

        assert!(parse_leef(&*data).is_err())
    }
}
