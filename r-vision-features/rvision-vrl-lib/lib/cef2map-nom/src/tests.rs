#[cfg(test)]
mod parse_cef_tests {
    use crate::parse_cef;

    #[test]
    fn test_non_cef_string() {
        let s = "this is not a cef string|key=value";
        assert!(parse_cef(s.into()).is_err())
    }

    #[test]
    fn test_malformed_cef_string() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1";
        assert!(parse_cef(s.into()).is_err())
    }

    #[test]
    fn test_simple() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        assert!(parse_cef(s.into()).is_ok())
    }

    #[test]
    fn test_simple_minor_verion() {
        let s = "CEF:0.1|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef(s.into()).unwrap();
    }

    #[test]
    fn test_simple_different_version() {
        let s = "CEF:1|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef(s.into()).unwrap();
    }

    #[test]
    fn test_simple_weird_version() {
        let s = "CEF:123.123|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef(s.into()).unwrap();
    }

    // #[test]
    // fn test_with_raw_event() {
    //   let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    //   let map = parse_cef(s.into()).unwrap();
    //   assert!(x.unwrap().get("rawEvent").is_some())
    // }

    #[test]
    fn test_without_raw_event() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        assert!(x.unwrap().get("rawEvent").is_none())
    }

    #[test]
    fn test_pri_facility() {
        let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("syslog_priority").is_some());
        assert!(x.get("syslog_facility").is_some());
    }

    #[test]
    fn test_no_pri_facility() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("syslog_priority").is_none());
        assert!(x.get("syslog_facility").is_none());
    }

    #[test]
    fn test_host_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_host_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    // #[test]
    // fn test_only_datetime() {
    //   let s = "<134>1 2022-02-14T03:17:30-08:00 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_some());
    //   assert!(x.get("ahost").is_none());
    // }
    //
    // #[test]
    // fn test_only_human_datetime() {
    //   let s = "<134>Feb 14 19:04:54 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_some());
    //   assert!(x.get("ahost").is_none());
    // }

    #[test]
    fn test_ipv4_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv4_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_datetime_rfc5424() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6localhost_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 ::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "::1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(
            x.get("ahost").unwrap(),
            "2001:db8:3333:4444:5555:6666:7777:8888"
        );
        assert!(x.get("at").is_some());
    }

    // #[test]
    // fn test_ipv6_and_human_datetime_rfc5424() {
    //   let s = "<134>1 Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "2001:db8:3333:4444:5555:6666:7777:8888");
    //   assert!(x.get("at").is_some());
    // }

    // Да за шо????777
    // #[test]
    // fn test_only_host() {
    //   let s = "<134>TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_none());
    //   assert!(x.get("ahost").is_some());
    // }
    //
    // #[test]
    // fn test_only_ipv4() {
    //   let s = "<134>127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_none());
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
    // }
    //
    // #[test]
    // fn test_only_ipv6localhost() {
    //   let s = "<134>::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "::1");
    //   assert!(x.get("at").is_none());
    // }
    //
    // #[test]
    // fn test_only_ipv6() {
    //   let s = "<134>2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "2001:db8:3333:4444:5555:6666:7777:8888");
    //   assert!(x.get("at").is_none());
    // }

    #[test]
    fn test_equals_inside_value() {
        let s = r"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|request=https://google.com&search\=rust";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("request").is_some());
        assert_eq!(x.get("request").unwrap(), "https://google.com&search=rust");
    }

    #[test]
    fn test_cef_headers_exist() {
        let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("deviceVendor").is_some());
        assert!(x.get("deviceProduct").is_some());
        assert!(x.get("deviceVersion").is_some());
        assert!(x.get("signatureId").is_some());
        assert!(x.get("name").is_some());
        assert!(x.get("severity").is_some());
    }

    #[test]
    fn test_cef_strange_headers_but_allowed() {
        let s = r#"<134>CEF:0|Ven\|dor\\|Pro\|\\duct\\\||\|20.0.560|6\|0\|0\\|\\User Signed In\\|3\\\\что-то|"#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();

        assert!(x.get("deviceVendor").is_some());
        assert!(x.get("deviceProduct").is_some());
        assert!(x.get("deviceVersion").is_some());
        assert!(x.get("signatureId").is_some());
        assert!(x.get("name").is_some());
        assert!(x.get("severity").is_some());

        assert_eq!(x.get("deviceVendor").unwrap(), r#"Ven|dor\"#);
        assert_eq!(x.get("deviceProduct").unwrap(), r#"Pro|\duct\|"#);
        assert_eq!(x.get("deviceVersion").unwrap(), r#"|20.0.560"#);
        assert_eq!(x.get("signatureId").unwrap(), r#"6|0|0\"#);
        assert_eq!(x.get("name").unwrap(), r#"\User Signed In\"#);
        assert_eq!(x.get("severity").unwrap(), r#"3\\что-то"#);
    }

    #[test]
    fn test_equals_key_value_with_space() {
        let s = r"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|key= value ";
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"key"#).is_some());
        assert_eq!(x.get(r#"key"#).unwrap(), r#"value"#);
    }

    #[test]
    fn test_equals_key_value_odd_slash() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo\=bar=buz foo\\\==bar\=\nwrapped"#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo=bar"#).is_some());
        assert_eq!(x.get(r#"foo=bar"#).unwrap(), r#"buz"#);
        assert!(x.get(r#"foo\="#).is_some());
        assert_eq!(x.get(r#"foo\="#).unwrap(), "bar=\nwrapped");
    }

    #[test]
    fn test_equals_key_value_even_slash() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo\\=bar\=buz foo\\\\=bar\r\nbuz\="#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo\"#).is_some());
        assert_eq!(x.get(r#"foo\"#).unwrap(), r#"bar=buz"#);
        assert!(x.get(r#"foo\\"#).is_some());
        assert_eq!(x.get(r#"foo\\"#).unwrap(), "bar\nbuz=");
    }

    #[test]
    fn test_equals_value_with_wrapping() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar слеш_и\\\==равно, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), r#"bar"#);
        assert!(x.get(r#"слеш_и\="#).is_some());
        assert_eq!(
            x.get(r#"слеш_и\="#).unwrap(),
            "равно, эр\nэн\nэрен\nэнэр\nэнэн\n\nэренэр\n\nконец"
        );
        assert!(x.get(r#"bar"#).is_some());
        assert_eq!(x.get(r#"bar"#).unwrap(), r#"buz"#);
    }

    #[test]
    fn test_use_labels() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|cs1=overlapped cs22Label=Параметр foo=original cs1Label=foo cs2Label=безКлюча cs22=Зн\\ач\=ение cs3=без\r\nзаголовка"#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), r#"original"#);
        assert!(x.get(r#"cs1"#).is_some());
        assert!(x.get(r#"cs1Label"#).is_some());
        assert!(x.get(r#"Параметр"#).is_none());
        assert_eq!(x.get(r#"cs1"#).unwrap(), r#"overlapped"#);
        assert!(x.get(r#"cs2Label"#).is_some());
        assert_eq!(x.get(r#"cs2Label"#).unwrap(), r#"безКлюча"#);
        assert!(x.get(r#"cs3"#).is_some());
        assert_eq!(x.get(r#"cs3"#).unwrap(), "без\nзаголовка");
        assert!(x.get(r#"безКлюча"#).is_none());
    }

    #[test]
    fn test_more_escape_symbols() {
        //
        // let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar с\\\r\что-то\\n\\\n\\\r\\\n\=\r\\\n\=\rлеш\r\\?\n\\?_и\\\==ра\r\rвно\n\n, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar с\\\rчто-то\\n\\\n\\\r\\\n\=\r\\\n\=\rлеш\r\\?\n\\?_и\\\==ра\r\rвно\n\n, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), "bar");
        assert!(x
            .get("с\\\nчто-то\\n\\\n\\\n\\\n=\n\\\n=\nлеш\n\\?\n\\?_и\\=")
            .is_some());
        assert_eq!(
            x.get("с\\\nчто-то\\n\\\n\\\n\\\n=\n\\\n=\nлеш\n\\?\n\\?_и\\=")
                .unwrap(),
            "ра\n\nвно\n\n, эр\nэн\nэрен\nэнэр\nэнэн\n\nэренэр\n\nконец"
        );
        assert!(x.get(r#"bar"#).is_some());
        assert_eq!(x.get(r#"bar"#).unwrap(), "buz");
    }

    // #[test]
    // fn test_invalid_escape_symbols_but_allowed() {
    //   // we mind single `\` not to fail right now
    //   let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|this one=ain\t \falling d\own foo=ba\r\j\n\r\n\\\\"#;
    //   let x = parse_cef(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get(r#"foo"#).is_some());
    //   assert_eq!(x.get(r#"foo"#).unwrap(), "ba\nj\n\n\\\\");
    //   assert!(x.get(r#"one"#).is_some());
    //   assert_eq!(x.get(r#"one"#).unwrap(), r#"aint falling down"#);
    // }

    #[test]
    fn test_complex_event_with_trailing_wrap() {
        let s = r#"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:${i}|A new process has been created.|Low| eventId=832805978 externalId=4688 msg=Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy. Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account. Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the\nuser chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group. Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not\nrequire administrative privilege, and the user does not choose to start the pr mrt=1620969336676 in=-2147483648 out=-2147483648 categorySignificance=/Informational categoryBehavior=/Execute/Start categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Resource/Process modelConfidence=4 severity=0 relevance=10 assetCriticality=0 priority=3 art=1620969353610 cat=Security deviceSeverity=Audit_success rt=1620969352000 dhost=maxsiem22.rvlab.local dst=10.99.10.83 destinationZoneID=ML8022AABABCDTFpYAT3UdQ\=\= destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dntdom=RVLAB destinationAssetId=4QHZAVnMBABCtIydGzz47jw\=\= duser=MAXSIEM22$ duid=0x3e7 dproc=C:\\Windows\\System32\\cmd.exe dlong=0.0 dlat=0.0 cs2=Detailed Tracking:Process Creation cs3=0x1a20 cs4=C:\\Windows\\system32\\cmd.exe /c handle.exe /accepteula -s -p 2200 2> nul cs5=0x898 cs6=TokenElevationTypeDefault (1) locality=1 cs1Label=Accesses cs2Label=EventlogCategory cs3Label=New Process ID cs4Label=Process Command Line cs5Label=Creator Process ID cs6Label=Process Information:Token Elevation Type cn1Label=LogonType cn2Label=CrashOnAuditFail cn3Label=Count ahost=arcsightforwarder01.rvlab.local agt=10.99.12.51 amac=00-50-56-B4-D6-1A av=7.9.0.8087.0 atz=Europe/Moscow at=superagent_ng dvchost=maxsiem22.rvlab.local dvc=10.99.10.83 deviceZoneID=ML8022AABABCDTFpYAT3UdQ\=\= deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 deviceNtDomain=RVLAB deviceAssetId=4QHZAVnMBABCtIydGzz47jw\=\= dtz=Europe/Moscow eventAnnotationStageUpdateTime=1620969336677 eventAnnotationModificationTime=1620969336677 eventAnnotationAuditTrail=1,1614762693554,root,Queued,,,,\n eventAnnotationVersion=1 eventAnnotationEventId=832805978 eventAnnotationFlags=0 eventAnnotationEndTime=1620969352000 eventAnnotationManagerReceiptTime=1620969336676 _cefVer=0.1 ad.arcSightEventPath=3jTY1VnMBABCsoYi6SMWJqA\=\= aid=3ooZnZnkBABCGUkN2aHe8kA\=\= "#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"eventAnnotationAuditTrail"#).is_some());
        assert_eq!(
            x.get(r#"eventAnnotationAuditTrail"#).unwrap(),
            "1,1614762693554,root,Queued,,,,"
        );
    }

    #[test]
    fn test_event_with_extra_spaces() {
        let s = r#"CEF:0|Sybase|ASE Audit|5.0|45|Sybase ASE Audit Event|Unknown| eventId=1186773866   msg=Log in   start=1653292300881  src=15.123.32.12  sourceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 23.3.3.3-23.255.255.255 "#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"eventId"#).is_some());
        assert_eq!(x.get(r#"eventId"#).unwrap(), "1186773866");
        assert!(x.get(r#"msg"#).is_some());
        assert_eq!(x.get(r#"msg"#).unwrap(), "Log in");
        assert!(x.get(r#"start"#).is_some());
        assert_eq!(x.get(r#"start"#).unwrap(), "1653292300881");
        assert!(x.get(r#"src"#).is_some());
        assert_eq!(x.get(r#"src"#).unwrap(), "15.123.32.12");
        assert!(x.get(r#"sourceZoneURI"#).is_some());
        assert_eq!(
      x.get(r#"sourceZoneURI"#).unwrap(),
      "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 23.3.3.3-23.255.255.255"
    );
    }

    #[test]
    fn test_event_extension_with_unescaped_but_valid_pipe_symbol() {
        let s = r#"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4663|An attempt was made to access an object.|Low| eventId=69814957 externalId=4663 categorySignificance=/Informational categoryBehavior=/Access categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Resource art=1655459035577 cat=Security deviceSeverity=Audit_success rt=1655459020678 dhost=cvm01.sea.land dst=10.99.111.2 destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dntdom=SEA duser=CVM01$ duid=0x3e7 dproc=C:\\Windows\\Sysmon.exe fname=C:\\Windows\\System32\\dbgcore.dll fileId=0x4304 fileType=File oldFileHash=UTF-8| cs1=ReadData (or ListDirectory) cs2=File System cs3=0xb28 cs1Label=Accesses cs2Label=EventlogCategory cs3Label=Process ID ahost=arc02.sea.land agt=10.99.110.110 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 amac=00-50-56-B4-94-B9 av=8.0.0.8322.0 atz=Europe/Moscow at=winc dvchost=cvm01.sea.land dvc=10.99.111.2 deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 deviceNtDomain=SEA dtz=Europe/Moscow geid=462921181018383 _cefVer=0.1 ad.EventRecordID=68302422 ad.Version=1 ad.ThreadID=6540 ad.Opcode=Info ad.ProcessID=4 ad.ObjectServer=Security ad.AccessMask=0x1 ad.ResourceAttributes=S:AI aid=3u58EV30BABCAmEJ-xo088Q\=\="#;
        let x = parse_cef(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"externalId"#).is_some());
        assert_eq!(x.get(r#"externalId"#).unwrap(), "4663");
    }

    #[test]
    fn malformed_cef() {
        let s = r#"CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1"#;
        let x = parse_cef(s.into());
        assert!(x.is_err());
    }

    #[test]
    fn invalid_utf8() {
        let s =
            b"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|k\xFFey= value".as_slice();
        let res = parse_cef(s.into());
        assert!(res.is_err());
    }
}

#[cfg(test)]
mod parse_cef_with_labels_tests {
    use crate::parse_cef_with_labels;

    #[test]
    fn test_non_cef_string() {
        let s = "this is not a cef string|key=value";
        assert!(parse_cef_with_labels(s.into()).is_err())
    }

    #[test]
    fn test_malformed_cef_string() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1";
        assert!(parse_cef_with_labels(s.into()).is_err())
    }

    #[test]
    fn test_simple() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        assert!(parse_cef_with_labels(s.into()).is_ok())
    }

    #[test]
    fn test_simple_minor_verion() {
        let s = "CEF:0.1|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef_with_labels(s.into()).unwrap();
    }

    #[test]
    fn test_simple_different_version() {
        let s = "CEF:1|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef_with_labels(s.into()).unwrap();
    }

    #[test]
    fn test_simple_weird_version() {
        let s = "CEF:123.123|Vendor|Product|20.0.560|600|User Signed In|3|";
        parse_cef_with_labels(s.into()).unwrap();
    }

    // #[test]
    // fn test_with_raw_event() {
    //   let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
    //   let map = parse_cef_with_labels(s.into()).unwrap();
    //   assert!(x.unwrap().get("rawEvent").is_some())
    // }

    #[test]
    fn test_without_raw_event() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        assert!(x.unwrap().get("rawEvent").is_none())
    }

    #[test]
    fn test_pri_facility() {
        let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("syslog_priority").is_some());
        assert!(x.get("syslog_facility").is_some());
    }

    #[test]
    fn test_no_pri_facility() {
        let s = "CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("syslog_priority").is_none());
        assert!(x.get("syslog_facility").is_none());
    }

    #[test]
    fn test_host_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_host_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    // #[test]
    // fn test_only_datetime() {
    //   let s = "<134>1 2022-02-14T03:17:30-08:00 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_some());
    //   assert!(x.get("ahost").is_none());
    // }
    //
    // #[test]
    // fn test_only_human_datetime() {
    //   let s = "<134>Feb 14 19:04:54 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_some());
    //   assert!(x.get("ahost").is_none());
    // }

    #[test]
    fn test_ipv4_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv4_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_datetime() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_datetime_rfc5424() {
        let s = "<134>1 2022-02-14T03:17:30-08:00 127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6localhost_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 ::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(x.get("ahost").unwrap(), "::1");
        assert!(x.get("at").is_some());
    }

    #[test]
    fn test_ipv6_and_human_datetime() {
        let s = "<134>Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("ahost").is_some());
        assert_eq!(
            x.get("ahost").unwrap(),
            "2001:db8:3333:4444:5555:6666:7777:8888"
        );
        assert!(x.get("at").is_some());
    }

    // #[test]
    // fn test_ipv6_and_human_datetime_rfc5424() {
    //   let s = "<134>1 Feb 14 19:04:54 2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "2001:db8:3333:4444:5555:6666:7777:8888");
    //   assert!(x.get("at").is_some());
    // }

    // Да за шо????777
    // #[test]
    // fn test_only_host() {
    //   let s = "<134>TEST CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_none());
    //   assert!(x.get("ahost").is_some());
    // }
    //
    // #[test]
    // fn test_only_ipv4() {
    //   let s = "<134>127.0.0.1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("at").is_none());
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "127.0.0.1");
    // }
    //
    // #[test]
    // fn test_only_ipv6localhost() {
    //   let s = "<134>::1 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "::1");
    //   assert!(x.get("at").is_none());
    // }
    //
    // #[test]
    // fn test_only_ipv6() {
    //   let s = "<134>2001:db8:3333:4444:5555:6666:7777:8888 CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|src=127.0.0.1 ";
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get("ahost").is_some());
    //   assert_eq!(x.get("ahost").unwrap(), "2001:db8:3333:4444:5555:6666:7777:8888");
    //   assert!(x.get("at").is_none());
    // }

    #[test]
    fn test_equals_inside_value() {
        let s = r"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|request=https://google.com&search\=rust";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("request").is_some());
        assert_eq!(x.get("request").unwrap(), "https://google.com&search=rust");
    }

    #[test]
    fn test_cef_headers_exist() {
        let s = "<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get("deviceVendor").is_some());
        assert!(x.get("deviceProduct").is_some());
        assert!(x.get("deviceVersion").is_some());
        assert!(x.get("signatureId").is_some());
        assert!(x.get("name").is_some());
        assert!(x.get("severity").is_some());
    }

    #[test]
    fn test_cef_strange_headers_but_allowed() {
        let s = r#"<134>CEF:0|Ven\|dor\\|Pro\|\\duct\\\||\|20.0.560|6\|0\|0\\|\\User Signed In\\|3\\\\что-то|"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();

        assert!(x.get("deviceVendor").is_some());
        assert!(x.get("deviceProduct").is_some());
        assert!(x.get("deviceVersion").is_some());
        assert!(x.get("signatureId").is_some());
        assert!(x.get("name").is_some());
        assert!(x.get("severity").is_some());

        assert_eq!(x.get("deviceVendor").unwrap(), r#"Ven|dor\"#);
        assert_eq!(x.get("deviceProduct").unwrap(), r#"Pro|\duct\|"#);
        assert_eq!(x.get("deviceVersion").unwrap(), r#"|20.0.560"#);
        assert_eq!(x.get("signatureId").unwrap(), r#"6|0|0\"#);
        assert_eq!(x.get("name").unwrap(), r#"\User Signed In\"#);
        assert_eq!(x.get("severity").unwrap(), r#"3\\что-то"#);
    }

    #[test]
    fn test_equals_key_value_with_space() {
        let s = r"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|key= value ";
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"key"#).is_some());
        assert_eq!(x.get(r#"key"#).unwrap(), r#"value"#);
    }

    #[test]
    fn test_equals_key_value_odd_slash() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo\=bar=buz foo\\\==bar\=\nwrapped"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo=bar"#).is_some());
        assert_eq!(x.get(r#"foo=bar"#).unwrap(), r#"buz"#);
        assert!(x.get(r#"foo\="#).is_some());
        assert_eq!(x.get(r#"foo\="#).unwrap(), "bar=\nwrapped");
    }

    #[test]
    fn test_equals_key_value_even_slash() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo\\=bar\=buz foo\\\\=bar\r\nbuz\="#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo\"#).is_some());
        assert_eq!(x.get(r#"foo\"#).unwrap(), r#"bar=buz"#);
        assert!(x.get(r#"foo\\"#).is_some());
        assert_eq!(x.get(r#"foo\\"#).unwrap(), "bar\nbuz=");
    }

    #[test]
    fn test_equals_value_with_wrapping() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar слеш_и\\\==равно, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), r#"bar"#);
        assert!(x.get(r#"слеш_и\="#).is_some());
        assert_eq!(
            x.get(r#"слеш_и\="#).unwrap(),
            "равно, эр\nэн\nэрен\nэнэр\nэнэн\n\nэренэр\n\nконец"
        );
        assert!(x.get(r#"bar"#).is_some());
        assert_eq!(x.get(r#"bar"#).unwrap(), r#"buz"#);
    }

    #[test]
    fn test_use_labels() {
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|cs1=overlapped cs22Label=Параметр foo=original cs1Label=foo cs2Label=безКлюча cs22=Зн\\ач\=ение cs3=без\r\nзаголовка"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), r#"overlapped"#);
        assert!(x.get(r#"cs1"#).is_none());
        assert!(x.get(r#"cs1Label"#).is_none());
        assert!(x.get(r#"Параметр"#).is_some());
        assert_eq!(x.get(r#"Параметр"#).unwrap(), r#"Зн\ач=ение"#);
        assert!(x.get(r#"cs2Label"#).is_some());
        assert_eq!(x.get(r#"cs2Label"#).unwrap(), r#"безКлюча"#);
        assert!(x.get(r#"cs3"#).is_some());
        assert_eq!(x.get(r#"cs3"#).unwrap(), "без\nзаголовка");
        assert!(x.get(r#"безКлюча"#).is_none());
    }

    #[test]
    fn test_more_escape_symbols() {
        //
        // let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar с\\\r\что-то\\n\\\n\\\r\\\n\=\r\\\n\=\rлеш\r\\?\n\\?_и\\\==ра\r\rвно\n\n, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|foo=bar с\\\rчто-то\\n\\\n\\\r\\\n\=\r\\\n\=\rлеш\r\\?\n\\?_и\\\==ра\r\rвно\n\n, эр\rэн\nэрен\r\nэнэр\n\rэнэн\n\nэренэр\r\n\rконец bar=buz"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"foo"#).is_some());
        assert_eq!(x.get(r#"foo"#).unwrap(), "bar");
        assert!(x
            .get("с\\\nчто-то\\n\\\n\\\n\\\n=\n\\\n=\nлеш\n\\?\n\\?_и\\=")
            .is_some());
        assert_eq!(
            x.get("с\\\nчто-то\\n\\\n\\\n\\\n=\n\\\n=\nлеш\n\\?\n\\?_и\\=")
                .unwrap(),
            "ра\n\nвно\n\n, эр\nэн\nэрен\nэнэр\nэнэн\n\nэренэр\n\nконец"
        );
        assert!(x.get(r#"bar"#).is_some());
        assert_eq!(x.get(r#"bar"#).unwrap(), "buz");
    }

    // #[test]
    // fn test_invalid_escape_symbols_but_allowed() {
    //   // we mind single `\` not to fail right now
    //   let s = r#"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|this one=ain\t \falling d\own foo=ba\r\j\n\r\n\\\\"#;
    //   let x = parse_cef_with_labels(s.into());
    //   assert!(x.is_ok());
    //   let x = x.unwrap();
    //   assert!(x.get(r#"foo"#).is_some());
    //   assert_eq!(x.get(r#"foo"#).unwrap(), "ba\nj\n\n\\\\");
    //   assert!(x.get(r#"one"#).is_some());
    //   assert_eq!(x.get(r#"one"#).unwrap(), r#"aint falling down"#);
    // }

    #[test]
    fn test_complex_event_with_trailing_wrap() {
        let s = r#"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:${i}|A new process has been created.|Low| eventId=832805978 externalId=4688 msg=Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy. Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account. Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the\nuser chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group. Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not\nrequire administrative privilege, and the user does not choose to start the pr mrt=1620969336676 in=-2147483648 out=-2147483648 categorySignificance=/Informational categoryBehavior=/Execute/Start categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Resource/Process modelConfidence=4 severity=0 relevance=10 assetCriticality=0 priority=3 art=1620969353610 cat=Security deviceSeverity=Audit_success rt=1620969352000 dhost=maxsiem22.rvlab.local dst=10.99.10.83 destinationZoneID=ML8022AABABCDTFpYAT3UdQ\=\= destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dntdom=RVLAB destinationAssetId=4QHZAVnMBABCtIydGzz47jw\=\= duser=MAXSIEM22$ duid=0x3e7 dproc=C:\\Windows\\System32\\cmd.exe dlong=0.0 dlat=0.0 cs2=Detailed Tracking:Process Creation cs3=0x1a20 cs4=C:\\Windows\\system32\\cmd.exe /c handle.exe /accepteula -s -p 2200 2> nul cs5=0x898 cs6=TokenElevationTypeDefault (1) locality=1 cs1Label=Accesses cs2Label=EventlogCategory cs3Label=New Process ID cs4Label=Process Command Line cs5Label=Creator Process ID cs6Label=Process Information:Token Elevation Type cn1Label=LogonType cn2Label=CrashOnAuditFail cn3Label=Count ahost=arcsightforwarder01.rvlab.local agt=10.99.12.51 amac=00-50-56-B4-D6-1A av=7.9.0.8087.0 atz=Europe/Moscow at=superagent_ng dvchost=maxsiem22.rvlab.local dvc=10.99.10.83 deviceZoneID=ML8022AABABCDTFpYAT3UdQ\=\= deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 deviceNtDomain=RVLAB deviceAssetId=4QHZAVnMBABCtIydGzz47jw\=\= dtz=Europe/Moscow eventAnnotationStageUpdateTime=1620969336677 eventAnnotationModificationTime=1620969336677 eventAnnotationAuditTrail=1,1614762693554,root,Queued,,,,\n eventAnnotationVersion=1 eventAnnotationEventId=832805978 eventAnnotationFlags=0 eventAnnotationEndTime=1620969352000 eventAnnotationManagerReceiptTime=1620969336676 _cefVer=0.1 ad.arcSightEventPath=3jTY1VnMBABCsoYi6SMWJqA\=\= aid=3ooZnZnkBABCGUkN2aHe8kA\=\= "#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"eventAnnotationAuditTrail"#).is_some());
        assert_eq!(
            x.get(r#"eventAnnotationAuditTrail"#).unwrap(),
            "1,1614762693554,root,Queued,,,,"
        );
    }

    #[test]
    fn test_event_with_extra_spaces() {
        let s = r#"CEF:0|Sybase|ASE Audit|5.0|45|Sybase ASE Audit Event|Unknown| eventId=1186773866   msg=Log in   start=1653292300881  src=15.123.32.12  sourceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 23.3.3.3-23.255.255.255 "#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"eventId"#).is_some());
        assert_eq!(x.get(r#"eventId"#).unwrap(), "1186773866");
        assert!(x.get(r#"msg"#).is_some());
        assert_eq!(x.get(r#"msg"#).unwrap(), "Log in");
        assert!(x.get(r#"start"#).is_some());
        assert_eq!(x.get(r#"start"#).unwrap(), "1653292300881");
        assert!(x.get(r#"src"#).is_some());
        assert_eq!(x.get(r#"src"#).unwrap(), "15.123.32.12");
        assert!(x.get(r#"sourceZoneURI"#).is_some());
        assert_eq!(
      x.get(r#"sourceZoneURI"#).unwrap(),
      "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 23.3.3.3-23.255.255.255"
    );
    }

    #[test]
    fn test_event_extension_with_unescaped_but_valid_pipe_symbol() {
        let s = r#"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4663|An attempt was made to access an object.|Low| eventId=69814957 externalId=4663 categorySignificance=/Informational categoryBehavior=/Access categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Resource art=1655459035577 cat=Security deviceSeverity=Audit_success rt=1655459020678 dhost=cvm01.sea.land dst=10.99.111.2 destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dntdom=SEA duser=CVM01$ duid=0x3e7 dproc=C:\\Windows\\Sysmon.exe fname=C:\\Windows\\System32\\dbgcore.dll fileId=0x4304 fileType=File oldFileHash=UTF-8| cs1=ReadData (or ListDirectory) cs2=File System cs3=0xb28 cs1Label=Accesses cs2Label=EventlogCategory cs3Label=Process ID ahost=arc02.sea.land agt=10.99.110.110 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 amac=00-50-56-B4-94-B9 av=8.0.0.8322.0 atz=Europe/Moscow at=winc dvchost=cvm01.sea.land dvc=10.99.111.2 deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 deviceNtDomain=SEA dtz=Europe/Moscow geid=462921181018383 _cefVer=0.1 ad.EventRecordID=68302422 ad.Version=1 ad.ThreadID=6540 ad.Opcode=Info ad.ProcessID=4 ad.ObjectServer=Security ad.AccessMask=0x1 ad.ResourceAttributes=S:AI aid=3u58EV30BABCAmEJ-xo088Q\=\="#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_ok());
        let x = x.unwrap();
        assert!(x.get(r#"externalId"#).is_some());
        assert_eq!(x.get(r#"externalId"#).unwrap(), "4663");
    }

    #[test]
    fn malformed_cef() {
        let s = r#"CEF:0|Vendor|Product|20.0.560|600|User Signed In|src=127.0.0.1"#;
        let x = parse_cef_with_labels(s.into());
        assert!(x.is_err());
    }

    #[test]
    fn invalid_utf8() {
        let s =
            b"<134>CEF:0|Vendor|Product|20.0.560|600|User Signed In|3|k\xFFey= value".as_slice();
        let res = parse_cef_with_labels(s.into());
        assert!(res.is_err());
    }
}
