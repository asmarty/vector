use bytes::Bytes;
use cef2map_nom::parse_cef_map;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

macro_rules! collection {
    // map-like
    ($($k:expr => $v:expr),* $(,)?) => {{
        core::convert::From::from([$(($k.into(), $v.into()),)*])
    }};
    // set-like
    ($($v:expr),* $(,)?) => {{
        core::convert::From::from([$($v,)*])
    }};
}

fn cef_4kb(c: &mut Criterion) {
    let s = Bytes::copy_from_slice(r#"CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:${i}|A new process has been created.|Low| eventId=832805978 \\C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD externalId=4688 msg=ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy. Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account. Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the\nuser chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group. Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not\nrequire administrative privilege, and the user does not choose to start the pr mrt=1620969336676 in=-2147483648 out=-2147483648 categorySignificance=/Informational categoryBehavior=/Execute/Start categoryDeviceGroup=/Operating System catdt=Operating System categoryOutcome=/Success categoryObject=/Host/Resource/Process modelConfidence=4 severity=0 relevance=10 assetCriticality=0 priority=3 art=1620969353610 cat=Security deviceSeverity=Audit_success rt=1620969352000 dhost=maxsiem22.rvlab.local dst=10.99.10.83 destinationZoneID=ML8022AABABCDTFpYAT3UdQ\=\= destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dntdom=RVLAB destinationAssetId=4QHZAVnMBABCtIydGzz47jw\=\= duser=MAXSIEM22$ duid=0x3e7 dproc=C:\\Windows\\System32\\cmd.exe dlong=0.0 dlat=0.0 cs2=Detailed Tracking:Process Creation cs3=0x1a20 cs4=C:\\Windows\\system32\\cmd.exe /c handle.exe /accepteula -s -p 2200 2> nul cs5=0x898 cs6=TokenElevationTypeDefault (1) locality=1 cs1Label=Accesses cs2Label=EventlogCategory cs3Label=New Process ID cs4Label=Process Command Line cs5Label=Creator Process ID cs6Label=Process Information:Token Elevation Type cn1Label=LogonType cn2Label=CrashOnAuditFail cn3Label=Count ahost=arcsightforwarder01.rvlab.local agt=10.99.12.51 amac=00-50-56-B4-D6-1A av=7.9.0.8087.0 atz=Europe/Moscow at=superagent_ng dvchost=maxsiem22.rvlab.local dvc=10.99.10.83 deviceZoneID=ML8022AABABCDTFpYAT3UdQ\=\= deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 deviceNtDomain=RVLAB deviceAssetId=4QHZAVnMBABCtIydGzz47jw\=\= dtz=Europe/Moscow eventAnnotationStageUpdateTime=1620969336677 eventAnnotationModificationTime=1620969336677 eventAnnotationAuditTrail=1,1614762693554,root,Queued,,,,\n eventAnnotationVersion=1 eventAnnotationEventId=832805978 eventAnnotationFlags=0 eventAnnotationEndTime=1620969352000 eventAnnotationManagerReceiptTime=1620969336676 _cefVer=0.1 ad.arcSightEventPath=3jTY1VnMBABCsoYi6SMWJqA\=\= aid=3ooZnZnkBABCGUkN2aHe8kA\=\= "#.as_bytes());

    let mut group = c.benchmark_group("cef");
    group.throughput(Throughput::Bytes(s.len() as u64));
    group.bench_function("4kb cef", |b| {

    let orig = collection! {
      "_cefVer" => "0.1",
      "ad.arcSightEventPath" => r#"3jTY1VnMBABCsoYi6SMWJqA=="#,
      "in" => "-2147483648",
      // severity => "Low",
      "agt" => "10.99.12.51",
      "ahost" => "arcsightforwarder01.rvlab.local",
      "aid" => r#"3ooZnZnkBABCGUkN2aHe8kA=="#,
      "amac" => "00-50-56-B4-D6-1A",
      "art" => "1620969353610",
      "assetCriticality" => "0",
      "at" => "superagent_ng",
      "atz" => "Europe/Moscow",
      "av" => "7.9.0.8087.0",
      "cat" => "Security",
      "catdt" => "Operating System",
      "categoryBehavior" => "/Execute/Start",
      "categoryDeviceGroup" => "/Operating System",
      "categoryObject" => "/Host/Resource/Process",
      "categoryOutcome" => "/Success",
      "categorySignificance" => "/Informational",
      "cn1Label" => "LogonType",
      "cn2Label" => "CrashOnAuditFail",
      "cn3Label" => "Count",
      "cs1Label" => "Accesses",
      "cs2" => "Detailed Tracking:Process Creation",
      "cs2Label" => "EventlogCategory",
      "cs3" => "0x1a20",
      "cs3Label" => "New Process ID",
      "cs4" => r#"C:\Windows\system32\cmd.exe /c handle.exe /accepteula -s -p 2200 2> nul"#,
      "cs4Label" => "Process Command Line",
      "cs5" => "0x898",
      "cs5Label" => "Creator Process ID",
      "cs6" => "TokenElevationTypeDefault (1)",
      "cs6Label" => "Process Information:Token Elevation Type",
      "destinationAssetId" => r#"4QHZAVnMBABCtIydGzz47jw=="#,
      "destinationZoneID" => r#"ML8022AABABCDTFpYAT3UdQ=="#,
      "destinationZoneURI" => "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255",
      "deviceAssetId" => r#"4QHZAVnMBABCtIydGzz47jw=="#,
      "deviceNtDomain" => "RVLAB",
      "deviceProduct" => "Microsoft Windows",
      "deviceSeverity" => "Audit_success",
      "deviceVendor" => "Microsoft",
      "deviceVersion" => "",
      "deviceZoneID" => r#"ML8022AABABCDTFpYAT3UdQ=="#,
      "deviceZoneURI" => "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255",
      "dhost" => "maxsiem22.rvlab.local",
      "dlat" => "0.0",
      "dlong" => "0.0",
      "dntdom" => "RVLAB",
      "dproc" => r#"C:\Windows\System32\cmd.exe"#,
      "dst" => "10.99.10.83",
      "dtz" => "Europe/Moscow",
      "duid" => "0x3e7",
      "duser" => "MAXSIEM22$",
      "dvc" => "10.99.10.83",
      "dvchost" => "maxsiem22.rvlab.local",
      "eventAnnotationAuditTrail" => "1,1614762693554,root,Queued,,,,",
      "eventAnnotationEndTime" => "1620969352000",
      "eventAnnotationEventId" => "832805978",
      "eventAnnotationFlags" => "0",
      "eventAnnotationManagerReceiptTime" => "1620969336676",
      "eventAnnotationModificationTime" => "1620969336677",
      "eventAnnotationStageUpdateTime" => "1620969336677",
      "eventAnnotationVersion" => "1",
      "eventId" => "832805978 \\C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD",
      "externalId" => "4688",
      "locality" => "1",
      "modelConfidence" => "4",
      "mrt" => "1620969336676",
      "msg" => "ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken ASD ASD C:/R-Vision/r-vector-features/modules/lib/sense/cef2map-nom/examples/flamegraph.rs ASDASDToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy. Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account. Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the\nuser chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group. Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not\nrequire administrative privilege, and the user does not choose to start the pr",
      "name" => "A new process has been created.",
      "out" => "-2147483648",
      "priority" => "3",
      "relevance" => "10",
      "rt" => "1620969352000",
      "severity" => "0",
      "signatureId" => "Microsoft-Windows-Security-Auditing:${i}"
    };
    b.iter(|| {
      let res = parse_cef_map(black_box(s.clone()), |v| v).unwrap();

      assert_eq!(res, orig);

      res
    });
  });
    group.finish();
}

criterion_group!(benches, cef_4kb);
criterion_main!(benches);
