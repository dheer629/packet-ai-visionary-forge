
// Protocol decoder functions for various network protocols

export const decodeTCPLayer = (packet: any, tcp: any) => {
  const srcPort = tcp['tcp.srcport'];
  const dstPort = tcp['tcp.dstport'];
  
  if (srcPort) packet.source = `${packet.source}:${srcPort}`;
  if (dstPort) packet.destination = `${packet.destination}:${dstPort}`;
  
  packet.protocol = 'TCP';
  
  // Extract TCP flags
  const flags = [];
  if (tcp['tcp.flags_tree']) {
    const flagsTree = tcp['tcp.flags_tree'];
    if (flagsTree['tcp.flags.syn'] === '1') flags.push('SYN');
    if (flagsTree['tcp.flags.ack'] === '1') flags.push('ACK');
    if (flagsTree['tcp.flags.psh'] === '1') flags.push('PSH');
    if (flagsTree['tcp.flags.fin'] === '1') flags.push('FIN');
    if (flagsTree['tcp.flags.rst'] === '1') flags.push('RST');
    if (flagsTree['tcp.flags.urg'] === '1') flags.push('URG');
  }
  
  packet.tcp = {
    srcPort,
    dstPort,
    seq: tcp['tcp.seq'],
    ack: tcp['tcp.ack'],
    flags: flags.join(' '),
    window: tcp['tcp.window_size'],
    length: tcp['tcp.len'] || '0'
  };
  
  const seqNum = tcp['tcp.seq'] || '';
  const ackNum = tcp['tcp.ack'] || '';
  const winSize = tcp['tcp.window_size'] || '';
  const len = tcp['tcp.len'] || '';
  
  packet.info = `${flags.join(' ')} Seq=${seqNum} Ack=${ackNum} Win=${winSize} Len=${len}`;
  packet.length = parseInt(len || packet.length || '0');
  
  return packet;
};

export const decodeUDPLayer = (packet: any, udp: any) => {
  const srcPort = udp['udp.srcport'];
  const dstPort = udp['udp.dstport'];
  const length = udp['udp.length'];
  
  if (srcPort) packet.source = `${packet.source}:${srcPort}`;
  if (dstPort) packet.destination = `${packet.destination}:${dstPort}`;
  
  packet.protocol = 'UDP';
  packet.length = parseInt(length || '0');
  
  packet.udp = {
    srcPort,
    dstPort,
    length
  };
  
  packet.info = `Src Port: ${srcPort}, Dst Port: ${dstPort}, Length: ${length}`;
  
  return packet;
};

export const decodeICMPLayer = (packet: any, icmp: any) => {
  packet.protocol = 'ICMP';
  
  const type = icmp['icmp.type'];
  const code = icmp['icmp.code'];
  
  packet.icmp = {
    type,
    code,
    typeName: getICMPTypeName(type, code)
  };
  
  packet.info = packet.icmp.typeName;
  
  return packet;
};

export const decodeICMPv6Layer = (packet: any, icmpv6: any) => {
  packet.protocol = 'ICMPv6';
  
  const type = icmpv6['icmpv6.type'];
  const code = icmpv6['icmpv6.code'];
  
  packet.icmpv6 = {
    type,
    code,
    typeName: getICMPv6TypeName(type, code)
  };
  
  packet.info = packet.icmpv6.typeName;
  
  return packet;
};

export const decodeDNSLayer = (packet: any, dns: any) => {
  packet.protocol = 'DNS';
  
  const queryName = dns['dns.qry.name'];
  const responseCode = dns['dns.resp.code'];
  const queryType = dns['dns.qry.type'];
  
  if (queryName) {
    packet.info = `Query ${queryType || 'A'}: ${queryName}`;
  } else if (responseCode !== undefined) {
    packet.info = `Response: ${getDNSResponseCodeName(responseCode)}`;
  } else {
    packet.info = 'DNS Query/Response';
  }
  
  return packet;
};

export const decodeHTTPLayer = (packet: any, http: any) => {
  packet.protocol = 'HTTP';
  
  const method = http['http.request.method'];
  const uri = http['http.request.uri'];
  const responseCode = http['http.response.code'];
  const responsePhrase = http['http.response.phrase'];
  
  if (method) {
    packet.info = `${method} ${uri || '/'}`;
  } else if (responseCode) {
    packet.info = `HTTP ${responseCode} ${responsePhrase || ''}`;
  } else {
    packet.info = 'HTTP Request/Response';
  }
  
  return packet;
};

export const decodeTLSLayer = (packet: any, tls: any) => {
  const version = tls['tls.record.version'];
  
  if (version === '0x0303') packet.protocol = 'TLSv1.2';
  else if (version === '0x0304') packet.protocol = 'TLSv1.3';
  else if (version === '0x0301') packet.protocol = 'TLSv1';
  else packet.protocol = 'TLS';
  
  const contentType = tls['tls.record.content_type'];
  
  if (contentType === '22') packet.info = 'Handshake';
  else if (contentType === '23') packet.info = 'Application Data';
  else if (contentType === '21') packet.info = 'Alert';
  else packet.info = 'TLS Record';
  
  return packet;
};

export const decodeDHCPLayer = (packet: any, dhcp: any) => {
  packet.protocol = 'DHCP';
  
  const messageType = dhcp['dhcp.option.dhcp_message_type'];
  const clientIP = dhcp['dhcp.ip.client'];
  const serverIP = dhcp['dhcp.ip.server'];
  
  if (messageType) {
    packet.info = getDHCPMessageTypeName(messageType);
    if (clientIP) packet.info += ` Client: ${clientIP}`;
    if (serverIP) packet.info += ` Server: ${serverIP}`;
  } else {
    packet.info = 'DHCP Message';
  }
  
  return packet;
};

export const decodeARPLayer = (packet: any, arp: any) => {
  packet.protocol = 'ARP';
  
  const opcode = arp['arp.opcode'];
  const senderIP = arp['arp.src.proto_ipv4'];
  const targetIP = arp['arp.dst.proto_ipv4'];
  const senderMac = arp['arp.src.hw_mac'];
  
  packet.arp = {
    operation: opcode === '1' ? 'Request' : 'Reply',
    senderMac,
    senderIP,
    targetMac: arp['arp.dst.hw_mac'],
    targetIP
  };
  
  if (opcode === '1') {
    packet.info = `Who has ${targetIP}? Tell ${senderIP}`;
  } else {
    packet.info = `${senderIP} is at ${senderMac}`;
  }
  
  return packet;
};

export const decodeSSHLayer = (packet: any, ssh: any) => {
  packet.protocol = 'SSH';
  const version = ssh['ssh.protocol'] || ssh['ssh.version'];
  packet.info = version ? `SSH ${version}` : 'SSH Protocol';
  return packet;
};

export const decodeFTPLayer = (packet: any, ftp: any) => {
  packet.protocol = 'FTP';
  const command = ftp['ftp.request.command'];
  const response = ftp['ftp.response.code'];
  
  if (command) {
    packet.info = `Command: ${command}`;
  } else if (response) {
    packet.info = `Response: ${response}`;
  } else {
    packet.info = 'FTP';
  }
  
  return packet;
};

export const decodeSMTPLayer = (packet: any, smtp: any) => {
  packet.protocol = 'SMTP';
  const command = smtp['smtp.req.command'];
  const response = smtp['smtp.response.code'];
  
  if (command) {
    packet.info = `Command: ${command}`;
  } else if (response) {
    packet.info = `Response: ${response}`;
  } else {
    packet.info = 'SMTP';
  }
  
  return packet;
};

export const decodePOPLayer = (packet: any, pop: any) => {
  packet.protocol = 'POP3';
  packet.info = 'POP3 Protocol';
  return packet;
};

export const decodeIMAPLayer = (packet: any, imap: any) => {
  packet.protocol = 'IMAP';
  packet.info = 'IMAP Protocol';
  return packet;
};

export const decodeNTPLayer = (packet: any, ntp: any) => {
  packet.protocol = 'NTP';
  const mode = ntp['ntp.mode'];
  packet.info = mode ? `NTP Mode ${mode}` : 'NTP';
  return packet;
};

export const decodeSNMPLayer = (packet: any, snmp: any) => {
  packet.protocol = 'SNMP';
  const version = snmp['snmp.version'];
  packet.info = version ? `SNMP v${version}` : 'SNMP';
  return packet;
};

// Helper functions for protocol type names
export const getICMPTypeName = (type: string, code: string) => {
  const typeNum = parseInt(type);
  switch (typeNum) {
    case 0: return 'Echo Reply';
    case 3: return 'Destination Unreachable';
    case 4: return 'Source Quench';
    case 5: return 'Redirect';
    case 8: return 'Echo Request';
    case 11: return 'Time Exceeded';
    case 12: return 'Parameter Problem';
    case 13: return 'Timestamp Request';
    case 14: return 'Timestamp Reply';
    default: return `ICMP Type ${type}`;
  }
};

export const getICMPv6TypeName = (type: string, code: string) => {
  const typeNum = parseInt(type);
  switch (typeNum) {
    case 1: return 'Destination Unreachable';
    case 2: return 'Packet Too Big';
    case 3: return 'Time Exceeded';
    case 4: return 'Parameter Problem';
    case 128: return 'Echo Request';
    case 129: return 'Echo Reply';
    case 133: return 'Router Solicitation';
    case 134: return 'Router Advertisement';
    case 135: return 'Neighbor Solicitation';
    case 136: return 'Neighbor Advertisement';
    default: return `ICMPv6 Type ${type}`;
  }
};

export const getDNSResponseCodeName = (code: string) => {
  const codeNum = parseInt(code);
  switch (codeNum) {
    case 0: return 'No Error';
    case 1: return 'Format Error';
    case 2: return 'Server Failure';
    case 3: return 'Name Error';
    case 4: return 'Not Implemented';
    case 5: return 'Refused';
    default: return `Response Code ${code}`;
  }
};

export const getDHCPMessageTypeName = (type: string) => {
  const typeNum = parseInt(type);
  switch (typeNum) {
    case 1: return 'DHCP Discover';
    case 2: return 'DHCP Offer';
    case 3: return 'DHCP Request';
    case 4: return 'DHCP Decline';
    case 5: return 'DHCP ACK';
    case 6: return 'DHCP NAK';
    case 7: return 'DHCP Release';
    case 8: return 'DHCP Inform';
    default: return `DHCP Type ${type}`;
  }
};
