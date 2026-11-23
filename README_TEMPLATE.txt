================================================================================
CS 3516 - Project 2 (WireView): Code Audit Report
================================================================================
Team Members:
1. Gus Smiley
2. Donovan Kennedy

Rename this file to README.txt before submitting. Plain text only.
Line numbers always refer to the ORIGINAL starter wireview.cpp.

--------------------------------------------------------------------------------
PART 1: READ BEFORE YOU RUN (Checkpoint Deliverable)
--------------------------------------------------------------------------------
Cite the file and line numbers (or man page section) you read for each answer.

1. Memory ownership in pcap_loop():
   Read `man pcap_loop` and the pcap_handler typedef in /usr/include/pcap/pcap.h.
   Who allocates the `const u_char *packet` buffer passed to packet_callback?
   How long is that pointer guaranteed to stay valid? What would go wrong if
   the callback saved `packet` in a std::vector<const u_char *> and parsed the
   saved pointers after pcap_loop() returned?
   Answer: 
   
   libpcap allocates the buffer that's passed to packet_callback. This makes it
   so that you don't have to call free() on the buffer, since your application
   is doing the allocating. The pointer is only guaranteed to remain valid for 1
   run of callback. Since the data gets deleted by libpcap after callback
   returns, saving it in a vector will cause undefined behavior such as
   overwritten data and segfaults. I looked at the Linux manual page for
   pcap_loop and dispatch, and lines 330-331 in the pcap.h file for this answer.


2. Bitfields and byte order:
   Open /usr/include/netinet/ip.h and find struct ip. The fields ip_hl and ip_v
   are declared in two different orders inside an #if. Why? Does ip_hl need
   ntohs() before you use it? Does ip_len? Explain the difference.
   Answer:

   The fields ip_hl and ip_v are declared in two different orders to account for
   the endianness of the bytes being sent. Some times, the bytes are little
   endian, and ip_hl comes before ip_v. Other times, the bytes are big endian
   and ip_v comes first. ip_len needs ntohs() but not ip_hl, because ip_hl is
   only 4 bits (< 1 byte), while ip_len is 2 bytes, meaning the numbers are
   affected by endianness.

3. Predict, then run:
   BEFORE running anything, read packet_callback() and write down what you
   expect the starter to print under "--- IPv4 Senders ---" for
   project2-dns.pcap. Then run it. If the output differs from your prediction,
   explain exactly why.
   Prediction: It will print out the sender and receiver in the wrong order,
   due to the program not adjusting the endianness of kv first and second.
   Actual: It did not print anything under those fields.
   Explanation: packet_callback() did not call ntohs() on the ether_type,
   causing the program to misinterpret what was going on with the IPv4's

--------------------------------------------------------------------------------
PART 2: AUDIT LOG
--------------------------------------------------------------------------------
Copy the entry formats below as many times as you need. There is no fixed
number of entries. See "Evidence standard" in the handout: an entry without
evidence earns no credit.

[Defect]
- Line number(s):
- Trigger (capture file + frame number):
- Observation (program output or sanitizer report vs. Wireshark, with filter):
- Root cause (header path + struct/field, or man page):
- Fix applied, and output after the fix:

[Not a Defect]
- Line number(s):
- Why it looks suspicious:
- Evidence it is correct (capture file + frame number, program vs. Wireshark):
- Explanation:

Did not call ntohs() on ether_type (defect)
- Line number(s): 89
- Trigger: project2-dns.pcap, all frames
- Observation: did not show IPv4 senders or recipients
- Root cause: system and capture user different endianness
- Fix applied, and output after the fix: added ntohs(), printed out the IPv4 senders and recipients

Did not call ntohs() on ether_type (defect)
- Line number(s): 117
- Trigger: edge-arp.pcap, all frames
- Observation: no entries under ARP participants
- Root cause: system and capture user different endianness
- Fix applied, and output after the fix: added ntohs(), printed out the ARP participants

Misaligned memory access
- Line number(s): 91
- Trigger: edge-ipopts.pcap, caught with the sanitizer
- Observation: memory misalignment error with the ipv4 on the sanitizer report
- Root cause: address ended in 0x8e (14), which isn't divisible by 4, so there's a misalignment error
- Fix applied, and output after the fix:
// Verify that the Ethernet and minimum IPv4 headers exist.
if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
   return;
}

// Copy IPv4 header into aligned local storage.
struct ip ip_hdr_storage;

std::memcpy(
   &ip_hdr_storage,
   packet + sizeof(struct ether_header),
   sizeof(struct ip)
);

const struct ip *ip_hdr = &ip_hdr_storage;

to replace the ip_hdr declaration that was already there. now the sanitizer report doesnt show the misalignment error

reading beyond captured packet buffer
- Line number(s): N/A (added code to fix it at line 159-161)
- Trigger: edge-snap34.pcap, all frames
- Observation: lots of errors on the sanitixer report
- Root cause: in the ARP section, the code did not check to make sure there was at least 42 bytes, the minimum # to read all of the ARP info
- Fix applied, and output after the fix:
if (pkthdr->caplen < 42) {
   return;
}

added to lines 159-161, and sanitixer report no longer gives errors

handle not being closed after the pcap_loop
- Line number(s): N/A (fix on line 259)
- Trigger: all of the edge pcaps
- Observation: all of the edge pcaps gave memory leak errors on their sanitizer report
- Root cause: pcap handle was only closed if a specific criteria was met
- Fix applied, and output after the fix:
pcap_close(handle);

added to line 259, sanitizer report no longer gives memory leak errors

--------------------------------------------------------------------------------
PART 3: WIRESHARK RECONCILIATION
--------------------------------------------------------------------------------
For each Wireshark value, give the display filter, tshark command or menu path
that produced it, so the grader can repeat it.

Metric                                   | Starter | Wireshark | Patched
-----------------------------------------+---------+-----------+--------
Total packets (project2-dns)             |         |           |
Duration, seconds (project2-dns)         |         |           |
Distinct IPv4 senders (project2-dns)     |         |           |
Distinct UDP dst ports (project2-dns)    |         |           |
ARP participants (project2-arp-storm)    |         |           |
ARP participants (project2-other-network)|         |           |
Packets to UDP port 53 (edge-ipopts)     |         |           |
ARP participants (edge-arp)              |         |           |
Distinct UDP dst ports (edge-mixed)      |         |           |
Skipped packets (edge-snap34)            |   n/a   |    *      |
Skipped packets (edge-shortframes)       |   n/a   |    *      |

* Wireshark has no single "skipped" statistic. List the frame numbers you
  expect to be skipped and the reason for each (Capture Length vs. the headers
  that frame needs).

How each Wireshark value was obtained:

--------------------------------------------------------------------------------
PART 4: BYTES TO FIELDS
--------------------------------------------------------------------------------
(a) One UDP packet from project2-dns.pcap. Frame number: ____
    Paste the hex dump, then label by byte offset: the three Ethernet fields,
    the IPv4 version/IHL byte (show the header-length calculation), protocol,
    source and destination addresses, and the UDP source and destination ports
    in hex and in decimal.

(b) One ARP packet from project2-arp-storm.pcap. Frame number: ____
    Paste the hex dump, then label by byte offset all nine ARP fields: hardware
    type, protocol type, hardware size, protocol size, opcode, sender MAC,
    sender IP, target MAC, target IP.

--------------------------------------------------------------------------------
PART 5: EXTENSION
--------------------------------------------------------------------------------
Describe in 3-5 sentences how your skipped-packet counter decides that a packet
is truncated or malformed, and which checks happen in which order.

--------------------------------------------------------------------------------
AI USE DISCLOSURE
--------------------------------------------------------------------------------
Tools used (or "none"): ChatGPT
What you used them for: Explaining what different errors from the sanitizer
reports meant, and writing code to fix those errors.
One case where a tool was wrong, or where you overruled it, and how you knew: It
wanted to change the way we constructed our eth headers, but I knew this was
unnecessary because we were not getting any errors with the eth headers.