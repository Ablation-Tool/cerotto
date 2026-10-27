
CEROTTO is a Digital Forensics and Incident Response tool, built for a modern problem: investigating AI agents.


Traditional DFIR tools answer: "A hacker or malware got onto this server and what files did they touch and what commands did they run?"


CEROTTO answers: "An autonomous AI agent was given access to a computer and what did the user ask it, what tools did the agent decide to call, and what actually happened on the operating system as a result?"

---


CEROTTO is designed to investigate the attacks conducted by autonomous agents.                                                                                                  
                                                                                                                                                                                                                  
  CEROTTO helps you reconstruct:                                                                                                 
                                                                                                                                                                                                                  
   • What the user asked the agent to do.                                                                                                                                                                         
   • Which tools the agent invoked.                                                                                                                                                                               
   • Which processes ran on the computer.                                                                                                                                                                         
   • Which files were accessed, created, or deleted.                                                                                                                                                              
   • Which network connections were made.                                                                                                                                                                         
                                                                                                                                                                                                                  
   It takes agent logs, Linux audit records, and disk evidence and combines them into one reviewable timeline. An optional AI assistant can summarize that timeline, but its observations and hypotheses must cite
   supporting events—and the assistant cannot run commands on the host.                                                                                                                                           
                                                                                                                                                                                                                  
   CEROTTO can help investigate:                                                                                                                                                                                  
                                                                                                                                                                                                                  
   • Prompt injection: A malicious document or website instructs an agent to ignore its original task.                                                                                                            
   • Tool abuse: The agent invokes shell, filesystem, browser, or MCP tools in unexpected ways.                                                                                                                   
   • Suspected data exfiltration: A prompt is followed by sensitive-file access and an outbound connection.                                                                                                       
   • Agent-driven hacking: An autonomous system runs scans, scripts, exploits, or persistence mechanisms on a host.                                                                                               
   • Compromised toolchains: Suspicious agent activity is followed by deleted files, modified configurations, or unusual processes.                                                                               
                                                                                                                                                                                                                  

                                                                                                                                                                                                        
                                                                                                                                                                                                        
                                                                                                                                                                                                                  
   CEROTTO helps responders see and verify that sequence without manually searching thousands of unrelated log lines. They can determine how much of the suspected attack is supported by evidence rather than    
   blaming the model based on timing or suspicious output alone.                                                                                                                                                  
                                                                                                                                                                                                                  
   An outbound connection does not, by itself, prove data exfiltration. Responders still need evidence of what was transmitted. CEROTTO separates those observed facts from hypotheses that require further       
   investigation.                                                                                                                                                                                                 
                                                                                                                                                                                                                  
   The important limitations are:                                                                                                                                                                                 
                                                                                                                                                                                                                  
   • CEROTTO needs agent logs, audit records, disk images, or similar evidence to exist.                                                                                                                          
   • Audit collection generally needs to be configured before an incident for complete process telemetry.                                                                                                         
   • It investigates after the fact; it does not block prompt injection or stop an attack in progress.                                                                                                            
   • It does not prove intent or automatically establish causation.                                                                                                                                               
   • AI-generated observations and hypotheses still require human verification.                                                                                                                                   
                                                                                                                                                                                                                  
   CEROTTO is therefore not an anti-jailbreak tool or an autonomous hacking platform. It is an incident-response and evidence-correlation layer for a world where AI agents can take real actions on real systems.
                                                                                                                                                                                                                  
