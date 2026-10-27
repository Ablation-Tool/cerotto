Cerotto is a Digital Forensics and Incident Response tool.

Built for a modern problem: investigating autonomous AI agent hacks and sandbox escapes.

---

Traditional DFIR tools answer: "A hacker or malware got onto this server and what files did they touch and what commands did they run?"


CEROTTO answers: "An autonomous AI agent was given access to a computer and what did the user ask it, what tools did the agent decide to call, and what actually happened on the operating system as a result?" 
                                                                                                                                                                                                                  
  Reconstruct:                                                                                                 
                                                                                                                                                                                                                  
   • What the user asked the agent to do.                                                                                                                                                                         
   • Which tools the agent invoked.                                                                                                                                                                               
   • Which processes ran on the computer.                                                                                                                                                                         
   • Which files were accessed, created, or deleted.                                                                                                                                                              
   • Which network connections were made.                                                                                                                                                                         
                                                                                                                                                                                                                  
                                                                                                                                                                                                                  
   Investigate:                                                                                                                                                                                  
                                                                                                                                                                                                                  
   • Prompt injection: A malicious document or website instructs an agent to ignore its original task.                                                                                                            
   • Tool abuse: The agent invokes shell, filesystem, browser, or MCP tools in unexpected ways.                                                                                                                   
   • Suspected data exfiltration: A prompt is followed by sensitive-file access and an outbound connection.                                                                                                       
   • Agent-driven hacking: An autonomous system runs scans, scripts, exploits, or persistence mechanisms on a host.                                                                                               
   • Compromised toolchains: Suspicious agent activity is followed by deleted files, modified configurations, or unusual processes.                                                                                                                                                  
