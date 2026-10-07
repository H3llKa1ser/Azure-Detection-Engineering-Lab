# Compact Sysmon lab config, kept in its own file for readability. Captures
# process creation with command line, network connections, remote-thread
# injection, process access (lsass), file creation, registry Run-key writes,
# Sysmon config changes, and DNS queries. Light exclusions keep it quiet.
locals {
  sysmon_config = <<-XML
    <Sysmon schemaversion="4.90">
      <HashAlgorithms>SHA256</HashAlgorithms>
      <DnsLookup>False</DnsLookup>
      <EventFiltering>
        <RuleGroup name="proc-create" groupRelation="or">
          <ProcessCreate onmatch="exclude">
            <Image condition="is">C:\Windows\System32\WindowsAzureGuestAgent.exe</Image>
          </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="net-connect" groupRelation="or">
          <NetworkConnect onmatch="exclude">
            <Image condition="image">MsMpEng.exe</Image>
          </NetworkConnect>
        </RuleGroup>
        <RuleGroup name="remote-thread" groupRelation="or">
          <CreateRemoteThread onmatch="include">
            <TargetImage condition="end with">.exe</TargetImage>
          </CreateRemoteThread>
        </RuleGroup>
        <RuleGroup name="proc-access-lsass" groupRelation="or">
          <ProcessAccess onmatch="include">
            <TargetImage condition="image">lsass.exe</TargetImage>
          </ProcessAccess>
        </RuleGroup>
        <RuleGroup name="file-create" groupRelation="or">
          <FileCreate onmatch="include">
            <TargetFilename condition="contains">\Startup\</TargetFilename>
            <TargetFilename condition="end with">.ps1</TargetFilename>
            <TargetFilename condition="end with">.bat</TargetFilename>
          </FileCreate>
        </RuleGroup>
        <RuleGroup name="registry-run" groupRelation="or">
          <RegistryEvent onmatch="include">
            <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
            <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
          </RegistryEvent>
        </RuleGroup>
        <RuleGroup name="dns" groupRelation="or">
          <DnsQuery onmatch="include">
            <QueryName condition="end with">.</QueryName>
          </DnsQuery>
        </RuleGroup>
      </EventFiltering>
    </Sysmon>
  XML
}
