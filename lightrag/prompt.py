GRAPH_FIELD_SEP = "<SEP>"

PROMPTS = {}

PROMPTS["DEFAULT_LANGUAGE"] = "English"
PROMPTS["DEFAULT_TUPLE_DELIMITER"] = "<|>"
PROMPTS["DEFAULT_RECORD_DELIMITER"] = "##"
PROMPTS["DEFAULT_COMPLETION_DELIMITER"] = "<|COMPLETE|>"
PROMPTS["process_tickers"] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

PROMPTS["DEFAULT_ENTITY_TYPES"] = ["Attacker", "Software", "Attack Pattern", "Attack Technique", "Mitigation", "Tactic", "Precondition", "Vulnerability", "Postcondition", "Target Entity"]

PROMPTS["entity_extraction"] = """-Goal-
Given a text document that is potentially relevant to this activity and a list of entity types, identify all entities of those types from the text and all relationships among the identified entities.
Use {language} as output language.

-Steps-
1. Identify all entities. For each identified entity, extract the following information:
- entity_name: Name of the entity, use same language as input text. If English, capitalized the name.
- entity_type: One of the following types: [
    ("type": "Attacker","description": "An entity involved in adversarial activities. It can be an individual, group, or organization. Attackers typically use software or attack techniques to carry out their attacks, and the relationship between attacker and software, as well as attacker and attack technique, is represented as a 'Use' relationship."),
    ("type": "Software","description": "Software that an attacker may use to conduct an attack, including commercial code, operating system utilities, or open-source software. It is typically classified into malicious software and normal tools. The relationship between software and attack techniques is represented as an 'Implement' relationship."),
    ("type": "Attack Pattern","description": "The method through which an attacker attempts to compromise a target. For example, sniffing network traffic where an attacker monitors network traffic between public or multicast network nodes in an attempt to capture sensitive information at the protocol level. Attackers can exploit vulnerabilities in the target entity using specific attack patterns, and the relationship between attack pattern and vulnerability is represented as an 'Exploit' relationship."),
    ("type": "Attack Technique","description": "The specific actions executed by an attacker during an attack. For example, bypassing User Account Control (UAC) to escalate privileges in the system. While attack techniques and attack patterns have overlapping concepts, each has its own characteristics, and the relationship between attack technique and attack pattern is represented as a 'Same_as' relationship."),
    ("type": "Mitigation","description": "Security measures or recommendations that can prevent the successful execution of attack techniques. The relationship between mitigation and attack technique is represented as a 'Mitigate' relationship."),
    ("type": "Tactic","description": "The objective that an attacker seeks to achieve through using techniques or taking actions. For example, an attacker may use phishing messages to gain access to a victim's system. The relationship between tactic and attack technique is represented as an 'Accomplish' relationship."),
    ("type": "Precondition","description": "The preliminary conditions that attackers need to master before exploiting vulnerabilities for attacks. Typically including the acquisition of vulnerability and environmental information, the attacker's tool resources, attack paths, the attacker's abilities, and even the attacker's innovative thinking. The relationship between prerequisites and vulnerabilities is represented as a 'premise' relationship.")
    ("type": "Vulnerability","description": "Attacker exploitable software vulnerabilities that can access systems or networks. Typically includes weaknesses and vulnerabilities, such as CVE (Common Vulnerabilities and Exposures). The relationship between hidden dangers and target objects is represented as an existence relationship Exist_in."),
    ("type": "Postcondition","description": "Attackers successfully exploited vulnerabilities to attack the target, resulting in subsequent impacts. These typically include information collection, privilege escalation, lateral expansion, persistent access control, etc. The relationship between the postconditions and the vulnerability is represented as 'affecting'.")
    ("type": "Target Entity","description": "Attacker's target of attack. Including product name, affected platforms (such as Windows, Linux, etc.), affected version names, etc.")]
- entity_description: Comprehensive description of the entity's attributes and activities
Format each entity as ("entity"{tuple_delimiter}<entity_name>{tuple_delimiter}<entity_type>{tuple_delimiter}<entity_description>)

2. From the entities identified in step 1, identify all pairs of (source_entity, target_entity) that are *clearly related* to each other.
For each pair of related entities, extract the following information:
- source_entity: name of the source entity, as identified in step 1
- target_entity: name of the target entity, as identified in step 1
- relationship_description: explanation as to why you think the source entity and the target entity are related to each other
- relationship_strength: a numeric score indicating strength of the relationship between the source entity and target entity
- relationship_keywords: one or more high-level key words that summarize the overarching nature of the relationship, focusing on concepts or themes rather than specific details
Format each relationship as ("relationship"{tuple_delimiter}<source_entity>{tuple_delimiter}<target_entity>{tuple_delimiter}<relationship_description>{tuple_delimiter}<relationship_keywords>{tuple_delimiter}<relationship_strength>)

3. Identify high-level key words that summarize the main concepts, themes, or topics of the entire text. These should capture the overarching ideas present in the document.
Format the content-level key words as ("content_keywords"{tuple_delimiter}<high_level_keywords>)

4. Return output in {language} as a single list of all the entities and relationships identified in steps 1 and 2. Use **{record_delimiter}** as the list delimiter.

5. When finished, output {completion_delimiter}

######################
-Examples-
######################
{examples}

#############################
-Real Data-
######################
Entity_types: {entity_types}
Text: {input_text}
######################
Output:
"""

PROMPTS["entity_extraction_examples"] = [
    """Example 1:

Entity_types: [Attacker, Software, Attack Pattern, Attack Technique, Mitigation, Tactic, Precondition, Vulnerability, Postcondition, Target Entity]
Text:
A sophisticated hacking group named "Red Team" has been actively targeting a major financial institution's online banking system. They have been using a custom-developed malware called "BlackViper" to exploit a known vulnerability in the system's web application, which is a SQL injection vulnerability (CVE-2024-1234). The vulnerability allows them to bypass the system's authentication mechanism and gain unauthorized access to customer accounts.

The Red Team employs a specific attack pattern where they first gather information about the target system's network topology and user behavior through social engineering and network scanning. Then, they use the BlackViper malware to inject malicious SQL queries into the web application, which is the attack technique they use. Their ultimate tactic is to steal sensitive customer data, such as account numbers and passwords, for financial gain.

To mitigate this attack, the financial institution has implemented a security patch for the SQL injection vulnerability and deployed an intrusion detection system (IDS) to monitor and alert on suspicious activities. However, the Red Team has already collected some initial information about the system and is looking for alternative attack paths.

################
Output:
("entity"{tuple_delimiter}"Red Team"{tuple_delimiter}"Attacker"{tuple_delimiter}"Red Team is a sophisticated hacking group targeting a major financial institution's online banking system."){record_delimiter}
("entity"{tuple_delimiter}"BlackViper"{tuple_delimiter}"Software"{tuple_delimiter}"BlackViper is a custom-developed malware used by Red Team to exploit vulnerabilities and carry out attacks."){record_delimiter}
("entity"{tuple_delimiter}"SQL Injection Attack Pattern"{tuple_delimiter}"Attack Pattern"{tuple_delimiter}"The attack pattern involves gathering information about the target system and then injecting malicious SQL queries into the web application."){record_delimiter}
("entity"{tuple_delimiter}"Malicious SQL Query Injection"{tuple_delimiter}"Attack Technique"{tuple_delimiter}"Red Team uses the technique of injecting malicious SQL queries into the web application to exploit the SQL injection vulnerability."){record_delimiter}
("entity"{tuple_delimiter}"Security Patch and IDS Deployment"{tuple_delimiter}"Mitigation"{tuple_delimiter}"The financial institution implements a security patch for the SQL injection vulnerability and deploys an IDS to monitor and alert on suspicious activities as mitigation measures."){record_delimiter}
("entity"{tuple_delimiter}"Steal Sensitive Customer Data"{tuple_delimiter}"Tactic"{tuple_delimiter}"Red Team's ultimate tactic is to steal sensitive customer data, such as account numbers and passwords, for financial gain."){record_delimiter}
("entity"{tuple_delimiter}"Information Gathering and Alternative Attack Path Search"{tuple_delimiter}"Precondition"{tuple_delimiter}"Red Team has already collected some initial information about the system and is looking for alternative attack paths as prerequisites for further attacks."){record_delimiter}
("entity"{tuple_delimiter}"SQL Injection Vulnerability (CVE-2024-1234) "{tuple_delimiter}"Vulnerability"{tuple_delimiter}"The system's web application has a known SQL injection vulnerability (CVE-2024-1234) that allows attackers to bypass the authentication mechanism."){record_delimiter}
("entity"{tuple_delimiter}"Unauthorized Access and Data Collection"{tuple_delimiter}"Postcondition"{tuple_delimiter}"Red Team has gained unauthorized access to customer accounts and is in the process of collecting sensitive data as a result of exploiting the vulnerability."){record_delimiter}
("entity"{tuple_delimiter}"Major Financial Institution's Online Banking System"{tuple_delimiter}"Target Entity"{tuple_delimiter}"The major financial institution's online banking system is the target of Red Team's attack, including its web application and customer accounts."){record_delimiter}
("relationship"{tuple_delimiter}"Red Team"{tuple_delimiter}"BlackViper"{tuple_delimiter}"Red Team uses BlackViper malware to carry out attacks on the target system."{tuple_delimiter}"Use"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"BlackViper"{tuple_delimiter}"Malicious SQL Query Injection"{tuple_delimiter}"BlackViper implements the attack technique of malicious SQL query injection to exploit the vulnerability."{tuple_delimiter}"Implement"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"SQL Injection Attack Pattern"{tuple_delimiter}"SQL Injection Vulnerability (CVE-2024-1234) "{tuple_delimiter}"The SQL injection attack pattern exploits the SQL injection vulnerability in the target system's web application."{tuple_delimiter}"Exploit"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"Malicious SQL Query Injection"{tuple_delimiter}"SQL Injection Attack Pattern"{tuple_delimiter}"Malicious SQL query injection is the same as the SQL injection attack pattern in this context."{tuple_delimiter}"Same_as"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"Security Patch and IDS Deployment"{tuple_delimiter}"Malicious SQL Query Injection"{tuple_delimiter}"The security patch and IDS deployment are intended to mitigate the malicious SQL query injection attack technique."{tuple_delimiter}"Mitigate"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"Steal Sensitive Customer Data"{tuple_delimiter}"Malicious SQL Query Injection"{tuple_delimiter}"The tactic of stealing sensitive customer data is accomplished through the attack technique of malicious SQL query injection."{tuple_delimiter}"Accomplish"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"Information Gathering and Alternative Attack Path Search"{tuple_delimiter}"SQL Injection Vulnerability (CVE-2024-1234) "{tuple_delimiter}"Information gathering and searching for alternative attack paths are prerequisites for exploiting the SQL injection vulnerability."{tuple_delimiter}"premise"{tuple_delimiter}6){record_delimiter}
("relationship"{tuple_delimiter}"SQL Injection Vulnerability (CVE-2024-1234) "{tuple_delimiter}"Major Financial Institution's Online Banking System"{tuple_delimiter}"The SQL injection vulnerability exists in the major financial institution's online banking system's web application."{tuple_delimiter}"Exist_in"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"Unauthorized Access and Data Collection"{tuple_delimiter}"SQL Injection Vulnerability (CVE-2024-1234) "{tuple_delimiter}"The postcondition of unauthorized access and data collection is a result of exploiting the SQL injection vulnerability."{tuple_delimiter}"affecting"{tuple_delimiter}8){record_delimiter}
("content_keywords"{tuple_delimiter}"cyber attack, financial institution, malware, SQL injection, vulnerability exploitation, data theft, security mitigation"){completion_delimiter}

#############################""",
    """Example 2:

Entity_types: [Attacker, Software, Attack Pattern, Attack Technique, Mitigation, Tactic, Precondition, Vulnerability, Postcondition, Target Entity]
Text:
Recently, a group of cybercriminals known as "Shadow Hackers" launched a series of attacks on a popular e-commerce platform. They utilized a widely available hacking tool called "WebCrack" to exploit a buffer overflow vulnerability in the platform's login module. This vulnerability, identified as CVE-2025-5678, could lead to the execution of arbitrary code on the server.

The Shadow Hackers followed a common attack pattern, where they first scanned the e-commerce platform for potential vulnerabilities using automated tools. Once they identified the buffer overflow vulnerability, they used WebCrack to craft and send specially designed packets to the login module, which is the attack technique they employed. Their main tactic was to gain unauthorized administrative access to the platform in order to manipulate product prices and inventory levels for their own benefit.

To counter these attacks, the e-commerce platform implemented a series of security measures. They updated the login module to fix the buffer overflow vulnerability and also deployed a web application firewall (WAF) to detect and block malicious traffic. However, the Shadow Hackers had already gained some initial foothold in the system and were attempting to expand their access.

################
Output:
("entity"{tuple_delimiter}"Shadow Hackers"{tuple_delimiter}"Attacker"{tuple_delimiter}"Shadow Hackers is a group of cybercriminals targeting a popular e-commerce platform."){record_delimiter}
("entity"{tuple_delimiter}"WebCrack"{tuple_delimiter}"Software"{tuple_delimiter}"WebCrack is a widely available hacking tool used by Shadow Hackers to exploit vulnerabilities."){record_delimiter}
("entity"{tuple_delimiter}"Buffer Overflow Exploitation Pattern"{tuple_delimiter}"Attack Pattern"{tuple_delimiter}"The attack pattern involves scanning for vulnerabilities and then exploiting a buffer overflow vulnerability using a hacking tool."){record_delimiter}
("entity"{tuple_delimiter}"Crafted Packet Injection"{tuple_delimiter}"Attack Technique"{tuple_delimiter}"Shadow Hackers use the technique of injecting crafted packets into the login module to exploit the buffer overflow vulnerability."){record_delimiter}
("entity"{tuple_delimiter}"Login Module Update and WAF Deployment"{tuple_delimiter}"Mitigation"{tuple_delimiter}"The e-commerce platform updates the login module and deploys a WAF to mitigate the attacks by Shadow Hackers."){record_delimiter}
("entity"{tuple_delimiter}"Unauthorized Administrative Access"{tuple_delimiter}"Tactic"{tuple_delimiter}"Shadow Hackers' main tactic is to gain unauthorized administrative access to manipulate product prices and inventory levels."){record_delimiter}
("entity"{tuple_delimiter}"Initial Foothold and Access Expansion"{tuple_delimiter}"Precondition"{tuple_delimiter}"Shadow Hackers have gained an initial foothold in the system and are attempting to expand their access as prerequisites for further attacks."){record_delimiter}
("entity"{tuple_delimiter}"Buffer Overflow Vulnerability (CVE-2025-5678) "{tuple_delimiter}"Vulnerability"{tuple_delimiter}"The e-commerce platform's login module has a buffer overflow vulnerability (CVE-2025-5678) that can be exploited."){record_delimiter}
("entity"{tuple_delimiter}"Server Code Execution and System Manipulation"{tuple_delimiter}"Postcondition"{tuple_delimiter}"As a result of exploiting the buffer overflow vulnerability, Shadow Hackers can execute arbitrary code on the server and manipulate the system."){record_delimiter}
("entity"{tuple_delimiter}"Popular E-commerce Platform"{tuple_delimiter}"Target Entity"{tuple_delimiter}"The popular e-commerce platform, including its login module and server, is the target of Shadow Hackers' attacks."){record_delimiter}
("relationship"{tuple_delimiter}"Shadow Hackers"{tuple_delimiter}"WebCrack"{tuple_delimiter}"Shadow Hackers use WebCrack to carry out attacks on the e-commerce platform."{tuple_delimiter}"Use"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"WebCrack"{tuple_delimiter}"Crafted Packet Injection"{tuple_delimiter}"WebCrack implements the attack technique of crafted packet injection to exploit the vulnerability."{tuple_delimiter}"Implement"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"Buffer Overflow Exploitation Pattern"{tuple_delimiter}"Buffer Overflow Vulnerability (CVE-2025-5678) "{tuple_delimiter}"The buffer overflow exploitation pattern exploits the buffer overflow vulnerability in the e-commerce platform's login module."{tuple_delimiter}"Exploit"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"Crafted Packet Injection"{tuple_delimiter}"Buffer Overflow Exploitation Pattern"{tuple_delimiter}"Crafted packet injection is the same as the buffer overflow exploitation pattern in this scenario."{tuple_delimiter}"Same_as"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"Login Module Update and WAF Deployment"{tuple_delimiter}"Crafted Packet Injection"{tuple_delimiter}"The login module update and WAF deployment are intended to mitigate the crafted packet injection attack technique."{tuple_delimiter}"Mitigate"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"Unauthorized Administrative Access"{tuple_delimiter}"Crafted Packet Injection"{tuple_delimiter}"The tactic of gaining unauthorized administrative access is accomplished through the attack technique of crafted packet injection."{tuple_delimiter}"Accomplish"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"Initial Foothold and Access Expansion"{tuple_delimiter}"Buffer Overflow Vulnerability (CVE-2025-5678) "{tuple_delimiter}"Gaining an initial foothold and attempting to expand access are prerequisites for exploiting the buffer overflow vulnerability."{tuple_delimiter}"premise"{tuple_delimiter}6){record_delimiter}
("relationship"{tuple_delimiter}"Buffer Overflow Vulnerability (CVE-2025-5678) "{tuple_delimiter}"Popular E-commerce Platform"{tuple_delimiter}"The buffer overflow vulnerability exists in the popular e-commerce platform's login module."{tuple_delimiter}"Exist_in"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"Server Code Execution and System Manipulation"{tuple_delimiter}"Buffer Overflow Vulnerability (CVE-2025-5678) "{tuple_delimiter}"The postcondition of server code execution and system manipulation is a result of exploiting the buffer overflow vulnerability."{tuple_delimiter}"affecting"{tuple_delimiter}8){record_delimiter}
("content_keywords"{tuple_delimiter}"cyber attack, e-commerce, hacking tool, buffer overflow, vulnerability exploitation, administrative access, security measures"){completion_delimiter}

#############################""",
    """Example 3:

Entity_types: [Attacker, Software, Attack Pattern, Attack Technique, Mitigation, Tactic, Precondition, Vulnerability, Postcondition, Target Entity]
Text:
A new strain of ransomware called "CryptoLock" has been identified, targeting Windows operating systems. The attackers behind CryptoLock, known as "Shadow Crew", use a combination of phishing emails and exploit kits to distribute the malware. Once the malware infects a system, it exploits a vulnerability in the Windows print spooler service, which allows it to escalate privileges and encrypt user files.

The attack pattern of Shadow Crew involves sending phishing emails with malicious attachments to unsuspecting users. When a user opens the attachment, the exploit kit is triggered, which then downloads and installs CryptoLock. The main tactic of Shadow Crew is to extort money from victims by demanding a ransom to decrypt their files.

To mitigate this threat, security experts recommend enabling Windows Defender's ransomware protection feature and keeping the operating system up to date with all security patches. However, some users may still fall victim to the attack if they are not cautious with emails and do not have proper security measures in place.

################
Output:
("entity"{tuple_delimiter}"Shadow Crew"{tuple_delimiter}"Attacker"{tuple_delimiter}"Shadow Crew is the group behind the CryptoLock ransomware, targeting Windows operating systems."){record_delimiter}
("entity"{tuple_delimiter}"CryptoLock"{tuple_delimiter}"Software"{tuple_delimiter}"CryptoLock is a strain of ransomware used by Shadow Crew to infect systems and encrypt user files."){record_delimiter}
("entity"{tuple_delimiter}"Phishing and Exploit Kit Distribution Pattern"{tuple_delimiter}"Attack Pattern"{tuple_delimiter}"The attack pattern involves sending phishing emails with malicious attachments and using exploit kits to distribute the ransomware."){record_delimiter}
("entity"{tuple_delimiter}"Malicious Attachment Triggering"{tuple_delimiter}"Attack Technique"{tuple_delimiter}"When a user opens the malicious attachment in the phishing email, the exploit kit is triggered, leading to the installation of CryptoLock."){record_delimiter}
("entity"{tuple_delimiter}"Ransomware Protection and Patching"{tuple_delimiter}"Mitigation"{tuple_delimiter}"Enabling Windows Defender's ransomware protection feature and keeping the operating system up to date are recommended mitigations against the threat."){record_delimiter}
("entity"{tuple_delimiter}"Extortion through Ransom Demand"{tuple_delimiter}"Tactic"{tuple_delimiter}"Shadow Crew's main tactic is to extort money from victims by demanding a ransom to decrypt their encrypted files."){record_delimiter}
("entity"{tuple_delimiter}"User Cautiousness and Security Measures"{tuple_delimiter}"Precondition"{tuple_delimiter}"Users being cautious with emails and having proper security measures in place are prerequisites for preventing the attack."){record_delimiter}
("entity"{tuple_delimiter}"Windows Print Spooler Vulnerability"{tuple_delimiter}"Vulnerability"{tuple_delimiter}"There is a vulnerability in the Windows print spooler service that allows privilege escalation and file encryption by the ransomware."{tuple_delimiter}"Exist_in"{tuple_delimiter}9){record_delimiter}
("entity"{tuple_delimiter}"File Encryption and Ransom Demand"{tuple_delimiter}"Postcondition"{tuple_delimiter}"As a result of exploiting the vulnerability, the ransomware encrypts user files and demands a ransom, affecting the victims."{tuple_delimiter}"affecting"{tuple_delimiter}8){record_delimiter}
("entity"{tuple_delimiter}"Windows Operating Systems"{tuple_delimiter}"Target Entity"{tuple_delimiter}"Windows operating systems are the target entities of the CryptoLock ransomware attack."{record_delimiter}
("relationship"{tuple_delimiter}"Shadow Crew"{tuple_delimiter}"CryptoLock"{tuple_delimiter}"Shadow Crew uses CryptoLock to carry out ransomware attacks on Windows systems."{tuple_delimiter}"Use"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"CryptoLock"{tuple_delimiter}"Malicious Attachment Triggering"{tuple_delimiter}"CryptoLock is installed through the attack technique of malicious attachment triggering in phishing emails."{tuple_delimiter}"Implement"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"Phishing and Exploit Kit Distribution Pattern"{tuple_delimiter}"Windows Print Spooler Vulnerability"{tuple_delimiter}"The phishing and exploit kit distribution pattern exploits the Windows print spooler vulnerability to infect systems."{tuple_delimiter}"Exploit"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"Malicious Attachment Triggering"{tuple_delimiter}"Phishing and Exploit Kit Distribution Pattern"{tuple_delimiter}"Malicious attachment triggering is a part of the phishing and exploit kit distribution pattern."{tuple_delimiter}"Same_as"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"Ransomware Protection and Patching"{tuple_delimiter}"Malicious Attachment Triggering"{tuple_delimiter}"Ransomware protection and patching are intended to mitigate the attack technique of malicious attachment triggering."{tuple_delimiter}"Mitigate"{tuple_delimiter}8){record_delimiter}
("relationship"{tuple_delimiter}"Extortion through Ransom Demand"{tuple_delimiter}"Malicious Attachment Triggering"{tuple_delimiter}"The tactic of extortion through ransom demand is accomplished through the attack technique of malicious attachment triggering."{tuple_delimiter}"Accomplish"{tuple_delimiter}7){record_delimiter}
("relationship"{tuple_delimiter}"User Cautiousness and Security Measures"{tuple_delimiter}"Windows Print Spooler Vulnerability"{tuple_delimiter}"User cautiousness and security measures are prerequisites for preventing the exploitation of the Windows print spooler vulnerability."{tuple_delimiter}"premise"{tuple_delimiter}6){record_delimiter}
("relationship"{tuple_delimiter}"Windows Print Spooler Vulnerability"{tuple_delimiter}"Windows Operating Systems"{tuple_delimiter}"The Windows print spooler vulnerability exists in Windows operating systems, making them susceptible to attacks."{tuple_delimiter}"Exist_in"{tuple_delimiter}9){record_delimiter}
("relationship"{tuple_delimiter}"File Encryption and Ransom Demand"{tuple_delimiter}"Windows Print Spooler Vulnerability"{tuple_delimiter}"The postcondition of file encryption and ransom demand is a result of exploiting the Windows print spooler vulnerability."{tuple_delimiter}"affecting"{tuple_delimiter}8){record_delimiter}
("content_keywords"{tuple_delimiter}"ransomware, Windows, phishing, exploit kit, extortion, security patch, user awareness"){completion_delimiter}

#############################""",
]

PROMPTS[
    "summarize_entity_descriptions"
] = """You are a helpful assistant responsible for generating a comprehensive summary of the data provided below.
Given one or two entities, and a list of descriptions, all related to the same entity or group of entities.
Please concatenate all of these into a single, comprehensive description. Make sure to include information collected from all the descriptions.
If the provided descriptions are contradictory, please resolve the contradictions and provide a single, coherent summary.
Make sure it is written in third person, and include the entity names so we the have full context.
Use {language} as output language.

#######
-Data-
Entities: {entity_name}
Description List: {description_list}
#######
Output:
"""

PROMPTS[
    "entiti_continue_extraction"
] = """MANY entities were missed in the last extraction.  Add them below using the same format:
"""

PROMPTS[
    "entiti_if_loop_extraction"
] = """It appears some entities may have still been missed.  Answer YES | NO if there are still entities that need to be added.
"""

PROMPTS["fail_response"] = "Sorry, I'm not able to provide an answer to that question."

PROMPTS["rag_response"] = """---Role---

You are a helpful assistant responding to questions about data in the tables provided.


---Goal---

Generate a response of the target length and format that responds to the user's question, summarizing all information in the input data tables appropriate for the response length and format, and incorporating any relevant general knowledge.
If you don't know the answer, just say so. Do not make anything up.
Do not include information where the supporting evidence for it is not provided.

When handling relationships with timestamps:
1. Each relationship has a "created_at" timestamp indicating when we acquired this knowledge
2. When encountering conflicting relationships, consider both the semantic content and the timestamp
3. Don't automatically prefer the most recently created relationships - use judgment based on the context
4. For time-specific queries, prioritize temporal information in the content before considering creation timestamps

---Target response length and format---

{response_type}

---Data tables---

{context_data}

Add sections and commentary to the response as appropriate for the length and format. Style the response in markdown."""

PROMPTS["keywords_extraction"] = """---Role---

You are a helpful assistant tasked with identifying both high-level and low-level keywords in the user's query.
Use {language} as output language.

---Goal---

Given the query, list both high-level and low-level keywords. High-level keywords focus on overarching concepts or themes, while low-level keywords focus on specific entities, details, or concrete terms.

---Instructions---

- Output the keywords in JSON format.
- The JSON should have two keys:
  - "high_level_keywords" for overarching concepts or themes.
  - "low_level_keywords" for specific entities or details.

######################
-Examples-
######################
{examples}

#############################
-Real Data-
######################
Query: {query}
######################
The `Output` should be human text, not unicode characters. Keep the same language as `Query`.
Output:

"""

PROMPTS["keywords_extraction_examples"] = [
    """Example 1:

Query: "How does international trade influence global economic stability?"
################
Output:
{
  "high_level_keywords": ["International trade", "Global economic stability", "Economic impact"],
  "low_level_keywords": ["Trade agreements", "Tariffs", "Currency exchange", "Imports", "Exports"]
}
#############################""",
    """Example 2:

Query: "What are the environmental consequences of deforestation on biodiversity?"
################
Output:
{
  "high_level_keywords": ["Environmental consequences", "Deforestation", "Biodiversity loss"],
  "low_level_keywords": ["Species extinction", "Habitat destruction", "Carbon emissions", "Rainforest", "Ecosystem"]
}
#############################""",
    """Example 3:

Query: "What is the role of education in reducing poverty?"
################
Output:
{
  "high_level_keywords": ["Education", "Poverty reduction", "Socioeconomic development"],
  "low_level_keywords": ["School access", "Literacy rates", "Job training", "Income inequality"]
}
#############################""",
]


PROMPTS["naive_rag_response"] = """---Role---

You are a helpful assistant responding to questions about documents provided.


---Goal---

Generate a response of the target length and format that responds to the user's question, summarizing all information in the input data tables appropriate for the response length and format, and incorporating any relevant general knowledge.
If you don't know the answer, just say so. Do not make anything up.
Do not include information where the supporting evidence for it is not provided.

When handling content with timestamps:
1. Each piece of content has a "created_at" timestamp indicating when we acquired this knowledge
2. When encountering conflicting information, consider both the content and the timestamp
3. Don't automatically prefer the most recent content - use judgment based on the context
4. For time-specific queries, prioritize temporal information in the content before considering creation timestamps

---Target response length and format---

{response_type}

---Documents---

{content_data}

Add sections and commentary to the response as appropriate for the length and format. Style the response in markdown.
"""

PROMPTS[
    "similarity_check"
] = """Please analyze the similarity between these two questions:

Question 1: {original_prompt}
Question 2: {cached_prompt}

Please evaluate the following two points and provide a similarity score between 0 and 1 directly:
1. Whether these two questions are semantically similar
2. Whether the answer to Question 2 can be used to answer Question 1
Similarity score criteria:
0: Completely unrelated or answer cannot be reused, including but not limited to:
   - The questions have different topics
   - The locations mentioned in the questions are different
   - The times mentioned in the questions are different
   - The specific individuals mentioned in the questions are different
   - The specific events mentioned in the questions are different
   - The background information in the questions is different
   - The key conditions in the questions are different
1: Identical and answer can be directly reused
0.5: Partially related and answer needs modification to be used
Return only a number between 0-1, without any additional content.
"""

PROMPTS["mix_rag_response"] = """---Role---

You are a professional assistant responsible for answering questions based on knowledge graph and textual information. Please respond in the same language as the user's question.

---Goal---

Generate a concise response that summarizes relevant points from the provided information. If you don't know the answer, just say so. Do not make anything up or include information where the supporting evidence is not provided.

When handling information with timestamps:
1. Each piece of information (both relationships and content) has a "created_at" timestamp indicating when we acquired this knowledge
2. When encountering conflicting information, consider both the content/relationship and the timestamp
3. Don't automatically prefer the most recent information - use judgment based on the context
4. For time-specific queries, prioritize temporal information in the content before considering creation timestamps

---Data Sources---

1. Knowledge Graph Data:
{kg_context}

2. Vector Data:
{vector_context}

---Response Requirements---

- Target format and length: {response_type}
- Use markdown formatting with appropriate section headings
- Aim to keep content around 3 paragraphs for conciseness
- Each paragraph should be under a relevant section heading
- Each section should focus on one main point or aspect of the answer
- Use clear and descriptive section titles that reflect the content
- List up to 5 most important reference sources at the end under "References", clearly indicating whether each source is from Knowledge Graph (KG) or Vector Data (VD)
  Format: [KG/VD] Source content

Add sections and commentary to the response as appropriate for the length and format. If the provided information is insufficient to answer the question, clearly state that you don't know or cannot provide an answer in the same language as the user's question."""
