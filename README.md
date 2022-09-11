# Content
- SDLC (Software Development Life Cycle)
- Security
- Introdution to OWASP Top 10 [2021]

## SDLC (Software Development Life Cycle)

![SDLC](image/README/SDLC%20Update.PNG)

- Requirement Analysis
    <br/>
    Build out requirements for what it is that you are going to develop
    <br/>
  - High level view of requirements and goals
  - Extracts requirements or requirements analysis
  - Clients have an idea of what they want - not how
  - Scope defined and agreed with
  - Prioritization of requirements
  - Slotting of resources

- Design
    <br/>
    Make your decisions around Technology and how it is going to actually be designed, what it is going to look like
    <br/>
  - Describe features and operations
    - Screen layout
    - Business rules
    - Procress diagrams
    - Pseudo code and documentation

  - Prototype work
  - Detailed design
    - Technology choices
    - System architecture

- Implementation
    <br/>
    Coding phase in SDLC, then you start testing and there is going to be some evolution

  - Input (Requirements and Design)
    - Requirements
    - Business Process
    - Business Rules
    - Software Design
    - Specification

  - Output
    - Deliverable Code

- Testing
    <br/>
    Testing phase in SDLC

  - Static Analysis (Code testing)
  - Dynamic Analysis (Running software testing)
  - Unit testing (Verify the functionality of specific code)
  - Integration testing (Verify the interfaces between components)
  - Interface testing (Testing data passed between units)
  - System testing (Testing a completely integrated system)

- Evolution
    <br/>
    Do some learnings from what you have built and put that into the requirements again to make enhancements to the development product that you have created

    Patch, Build, Test, Prod:
    <br/>
    You want to make sure that if there is any issues found such as security or even just defects, you want to patch those issues then rebuild, retest and then push it to production

<hr/>

## Security

Security is anything you do to protect an <u>asset</u> that is <u>vulnerable</u> to some <u>attack</u>, <u>failure</u>, or <u>error</u> [threats]

- **Asset**
    <br/>
    An **asset** is anything you deem to have **value**
    <br/>
    An asset may be valuable because:
  - It <u>holds</u> its value (E.g. gold/diamonds)
  - It <u>produces</u> value (E.g. Technology space, a server in a data center - running applications produce value to organization)
  - It <u>provides access</u> to value (E.g. a PIN number to a bank account to get money - something that needs to be protected)

- **Vulnerability**
    <br/>
    A vulnerability is any weakness in an asset that makes it susceptible to attack of failure

- **Attack**
    <br/>
    An attack is any <u>intentional</u> action that can reduce the value of an asset
    <br/>
    E.g. An attacker might perform a DDoS attack on that web server to reduce value for organisation intentionally

- **Failures + Errors**
    <br/>
    Failures and errors are <u>unintentional</u> actions that can reduce the value of an asset
    <br/>
    E.g. There might be an unplanned outage because of a power outage or maybe a new push for a patch that gets pushed at web server that does not work that creates an outage for that web server, making it unavailable for organisation so it reduce value unintentionally

Attacks, Failures and Errors are actions that we collectively refer to as <u>threats</u>

### Security Goals ("Anything")

Security, an more specifically Cybersecurity, can be understood as a set of goals

These goals are specifically defined by how we measure an asset's value

How does value define our security goals?

- The goal of security is to protect an asset's <u>value</u> from threats

1. Determine what assets we want to protect
2. Learn how the asset works and interacts with other things
3. Determine how our asset's value is reduced directly and indirectly
4. Take steps to mitigate the threats

We must consider the unique nature of it assets and capabilities when considering security goals.

#### CIA prinicples

When we protect something that provides access value, we are maintaining its confidentiality

- **Confidentiality**
    <br/>
    Information is only available to those who should have access (we can do this through encryption and HTTPS when we talking about browser traffic)

When we protect something that holds its value, we are maintaining its integrity

- **Integrity**
    <br/>
    Data is known to be correct and trusted (we can do this through hashing, checksum, sometimes digital signatures)

When we protect something that produces value, we are maintaining its availability

- **Availability**
    <br/>
    Information is available for use by legitimate users when it is needed (we can do this through building high availability and redundancy into our system)

**Real World Example**

- About a rocket
  - List assets
        <br/>
        (identifies what is actually on the rocket)
        <br/>
        Rocket itself, the food, the fuel, the water, the payload that is within the rocket, the equipment, the manifest, etc.

  - List vulnerabiltiies
        <br/>
        (possible vulnerabilties that impact rocket)
        <br/>
        A weak heat shield, faulty equipment, the hole could be too thin, etc.

  - List threats
        <br/>
        (attacks, failures, errors that impact rocket)
        <br/>
        Space debris, atmosphere, weather, pilot error, etc.

- How we secure it
    <br/>
    Based on the list of vulnerabilties and threats, we can have different ways that we could mitigate it.
    <br/>
    For instance, we could make the hole thicker or with using more duarble material. However, that could also alter things in the sense that we might make the rocket heavier and therefore, we would need more fuel to get it up or we could have less cargo space.
    <br/>
    Hence, the concept is making sure that the mitigations and the security that we put around our assets are in line with what the actual assets value is and make sure that we're not compromising the asset further by creating more complicated mitigations or remediation strategies.

We have well defined goals and security mechanisms, but some mechanisms are better because they fit <u>security principles</u>

Security principles aid in selecting or designing the correct mechanisms to implement our goals

Protection of information in computer systems [Doc]
<br/>
https://web.mit.edu/Saltzer/www/publications/protection/

![Protection of Information in computer systems](image/README/Protection%20of%20Information%20in%20computer%20systems.png)

![Security Pyramid](image/README/Security%20Pyramid.PNG)

OWASP WebGoat
<br/>
https://owasp.org/www-project-webgoat/

<hr/>

## Introduction to OWASP Top 10 [2021]

**1. Broken Access Control**
<br/>
Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other user's accounts, view sensitive files, modify other users' data, change access rights, etc.

**2. Cryptographic Failures**
<br/>
Failure to sufficiently protect data in transit or rest from exposure to unauthorized individuals. This can include poor usage of encryption or the lack of encryption all together.

**3. Injection**
<br/>
Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**4. Insecure Design**
<br/>
Failing to build security into the application early in the design process through a process of threat modeling, and secure design patterns and principles.

**5. Security Misconfiguration**
<br/>
Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigurated HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.

**6. Vulnerable and Outdated Components**
<br/>
Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

**7. Identification and Authentication Failure**
<br/>
Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, ot to exploit other implementation flaws to assume other users' identities temporarily or permanently.

**8. Software and Data Integrity Failures**
<br/>
Code or infrastructure that does not properly protect against integrity failures like using plugins from untrusted sources that can lead to a compromise.

**9. Insufficient Logging and Monitoring Failures**
<br/>
Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.

**10. Server-Side Request Forgery**
<br/>
SSRF occurs when an application fetches resources without validating the destination URL. This can be taken advantage of by an attacker who is able to enter a destination of their choosing.

### OWASP Help

OWASP offers that are great hints and series and frameworks that can be leveraged during the development process and all throughout the testing, the application testing and development process.

### OWASP Projects

- **Flagship**
<br/>
The OWASP Flagship destination is given to projects that have demonstrated strategic value to OWASP and application security as a whole
<br/>

- **Lab**
<br/>
OWASP Labs projects represent projects that have produced a deliverable of value
<br/>

- **Incubator**
<br/>
OWASP Incubator projects represent the experimental playground where projects are still being fleshed out, ideas are still being proven and development is still underway
<br/>

- **Low Activity**
<br/>
These projects had no release in at least a year. However, have shown to be valuable tools Code [Low Activity] Health Check February 2016

### How to start with OWASP

OWASP Top 10: the classic guideline
<br/>
https://owasp.org/www-project-top-ten/

OWASP Cheat Sheets to get into stuff without getting annoyed
<br/>
https://github.com/OWASP/CheatSheetSeries

Tools:

- Security Shephard
<br/>
https://github.com/OWASP/SecurityShephard

- WebGoat
<br/>
https://owasp.org/www-project-webgoat/

- OWASP Juice Shop
<br/>
https://owasp.org/www-project-juice-shop/

- OWASP ZAP (Zed Attack Proxy)
<br/>
<https://www.zaproxy.org/>

- OWTF (Offensive Web Testing Framework)
<br/>
<https://owasp.org/www-project-owtf/>

- OWASP ASVS
<br/>
<https://owasp.org/www-project-application-security-verification-standard/>

- Secure Coding Practices Quick Reference Guide
<br/>
<https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/>

- Java HTML Sanitizer
<br/>
<https://owasp.org/www-project-java-html-sanitizer/>

- CSRF Guard Project
<br/>
<https://owasp.org/www-project-csrfguard/>

- ESAPI
<br/>
<https://owasp.org/www-project-enterprise-security-api/>

- Developers Guide
<br/>
<https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/>

- Security Knowledge Framework
<br/>
<https://owasp.org/www-project-security-knowledge-framework/>

- OWASP Testing Guide
<br/>
<https://owasp.org/www-project-web-security-testing-guide/>

- Code Review Guidelines
<br/>
<https://owasp.org/www-project-code-reviews-guide/>

- Dependency Check
<br/>
<https://owasp.org/www-project-dependency-check/>

- Dependency Track
<br/>
<https://owasp.org/www-project-dependency-track/>

- DefectDojo
<br/>
<https://owasp.org/www-project-defectdojo/>

### SANS 25

<https://www.sans.org/top25-software-errors/>

![SANS 25](image/README/SANS%20Top%2025.PNG)

**Examples in the Top 25**
![Example SANS Top 25](image/README/Example%20SANS%20Top%2025.PNG)

![Example SANS Top 25 (2)](image/README/Example%20SANS%20Top%2025%20(2).PNG)

### OWASP vs SANS

![OWASP vs SANS](image/README/OWASP%20vs%20SANS.PNG)

### Threat Actors and Definition

- **Confidentiality**
<br/>
Concept of preventing the disclosure of information to unauthorized parties
<br/>

- **Integrity**
<br/>
Refers to protecting data from unauthorized alteration
<br/>

- **Availability**
<br/>
Access to systems by authorized personnel can be expressed as the system's availability
<br/>

- **Authentication**
<br/>
Authentication is the process of determining the identity of a user
<br/>

- **Authorization**
<br/>
Authorization is the process of applying access control rules to a user process, determining whether or not a particular user process can access an object
<br/>

- **Accounting (Audit)**
<br/>
Accounting is a means of measuring activity
<br/>

- **Non-Repudiation**
<br/>
Non-Repudiation is the concept of preventing a subject from denying a previous action with an object in a system
<br/>

- **Least Privilege**
<br/>
Subject should have only the necessary rights and privileges to perform its current task with no additional rights and privileges
<br/>

- **Separation of Duties**
<br/>
Ensures that for any given task, more than one individual needs to be involved
<br/>

- **Defense in Depth**
<br/>
Defense in depth is also known by the terms layered security (or defense) and diversity defense
<br/>

- **Fail Safe**
<br/>
When a system experiences a failure, it should fail to a safe state (Doors open when there is a power failure)
<br/>

- **Fail Secure**
<br/>
The default state is locked or secured. So a fail secure lock locks the door when power is removed.
<br/>

- **Single point of failure**
<br/>
A single point of failure is any aspect of a system that, if it fails, the entire system 

#### Types of attackers

- **Script Kiddies**
  - Low skill
  - Looking for easy and simple attacks
  - Motivated by revenge or fame

- **Hacktivist**
  - Moderate to high skill
  - Looking to make an example of an organisation
  - Motivated by activism

- **Hackers**
  - High skill
  - Looking to understand how things work
  - Motivation varies

- **Cyber Criminals**
  - High skill
  - Looking for financial exploits
  - Motivated money (Ransomware, Cryptojacking)

- **Advanced Persistent Threat**
  - Very high skill, deep pockets
  - Looking to commit cyber attacks in order to weaken a political advesary
  - Driven largely by national interest

#### Defense effort against threat actors
![Defense effort against threat actors](image/README/Defense%20effort%20against%20threat%20actors.PNG)

### Identifying Vulnerabilities
- **CVE (Common Vulnerabilities and Exposure)**
https://cve.mitre.org/cve/

  - Common Vulnerabiltiies and Exposures is a list of common identifiers for publicly known cyber security vulnerabiltiies
  
    - One identifier for one vulnerability with one standardized description
    - A dictionary rather than a database
    - The way to interoperability and better security coverage
    - A basis for evaluation among services, tools and database
    - Industry-endorsed via the CVE Numbering Authorities, CVE Board, and numerous products and services that include CV

- **CVSS (Common Vulnerability Scoring System)**
https://nvd.nist.gov/vuln-metrics/cvss

  - Common Vulnerability Scoring Sytem provides a way to capture the principal characteristics of a vulnerability and produce a numerical score reflecting its severity. The numerial score can then be translated into a qualitative representation (such as low, medium, high, and critical) to help organisations properly assess and prioritize their vulnerability management processes
   
    - Calcuating a score
      https://www.first.org/cvss/calculator/3.0 

    - Example CVE with a CVSS score
      https://www.nvd.nist.gov/vuln/detail/CVE-2017-14977

- **CWE (Common Weakness Enumeration)**
https://cwe.mitre.org/

  - Common Weakness Enumeration is a community-developed list of common software security weaknesses. It serves as a common language, a measuring stick for software security tools, and as a baseline for weakness identification, mitigation, and prevent efforts
  
  - As its core, the Common Weakness Enumeration is a list of software weaknesses types
  
  - Three types:
    - **Research**
      This view is intended to facilitate research into weaknesses, including their inter-dependencies and their role in vulnerabilities

    - **Development**
      This view organizes weaknesses around concepts that are frequently used or encountered in software development

    - **Architecture**
      This view organizes weaknesses according to common architectural security tactics

### Defense of depth
**Exploitation** of a **vulnerability** by a **threat** results in **risk**.

**Anatomy of an attack**
- Vulnerability: Adobe Flash CVE-2016-0960
- Exploit: Code written to take advantage of the vulnerability
- Payload: Ransomware, Trojan, RAT, keylogger, etc.

**Defense in depth** is an approach to cybersecurity in which a series of defensive mechanisms are layered in order to protect valuable data and information. If one mechanism fails, another setps up immediately to thwart an attack.

**What does it look like in the Cyber World**
![Cyber World](image/README/CyberWorld.PNG)

- Do not rely on defense in depth to always protect your app
- Systems fail they can be circumvented by the weakest link
- Your app may not always be behind those defenses

### Proxy Tools
In normal web interaction between a client and an application, there is a HTTP request and response.

Your application is expecting requests to come in from a client. And the client could be a browser/mobile app/API which is going to make a request to your application and it is going to hit the web server.

Depending on what your application is and how its architecture is built, it is going to take that request and process it and return a response.

So this request and response interaction between the client and application is an HTTPS communication.

![Normal Web Interaction](image/README/Normal%20web%20interaction.PNG)

Hence, what a proxy does, where proxy tool does, is that it sits between your browser and the web server and will actually proxy or capture that traffic and before ift is sent to the web server. This gives you the ability to see what the request is and what that request looks like before it goes to web server and what that response from the web server is coming back (able to capture both the request and response - acts as an intermediary between browser and web server)

![Proxy](image/README/Proxy.PNG)

Different tools:
- https://www.charlesproxy.com/
- https://www.telerik.com/fiddler
- https://httptoolkit.tech/
- Browser "Developer Tools"

### API Security
**Application Programming Interfaces (APIs)** allow the creation of discrete functionality that is available through a function or HTTP call to the functionality.

This allows for a modular approach to building an overall application.

For instance, JavaScript has APIs available that are built on top of the base language that allow the developer to integrate additional functionality:
- **Browser APIs**
Built into the browser, these expose data from the browser and environment that the browser is running in

- **3rd Party APIs**
These are APIs that are pulled in from external sources that allow you to retrieve data and functionality from that 3rd party 

**Difference between APIs and Standard application**
![APIs vs Standard App](image/README/APIs%20vs%20Standard%20App.PNG)


#### OWASP API Security Top 10
| Broken object level authorization | Mass assignment |
| :---:            |     :---:      |
| Broken authentication | Security misconfiguration  |
| Excessive data exposure | Injection  |
| Lack of resource and rate limiting | Improper assets management  |
| Broken function level authorization | Insufficient logging and monitoring  |


##### Broken Object Level Authorization
-  **Definition**
<br/>
Attacker substitutes ID of their resource in API call with an ID of a resource belonging to another user. Lack of proper authorization checks allows access. This attack is also known as IDOR (Insecure Direct Object Reference)

- **Example**
<br/>
An API that allows for an attacker to replace parameters in the URL that allows the attackers to have access to an API that they should not have access to. The API is not checking permissions and lets the call through.

- **Prevention**
  - Implement access checks on every call
  - Do not rely on user supplied IDs, only use IDs in the session object
  - Use random, non-guessable IDs

##### Broken Authentication
-  **Definition**
<br/>
Poorly implemented API authentication allowing attackers to assume other users' identities.

- **Example**
<br/>
Unprotected APIs, weak authentication, not rotating or reusing API keys, poor password usage, lack of token validation and weak handling

- **Prevention**
  - Check all authentication methods and use standard authentication, token generation/management, password storage, and MFA
  - Implement a strong password reset API
  - Authenticate the client calls to API
  - Use rate-limitations to avoid brute forcing

##### Excessive Data Exposure
-  **Definition**
<br/>
API exposing a lot more data than the client legitimately needs, relying on the client to do the filtering. Attacker goes directly to the API and has it all.

- **Example**
<br/>
Returning full data objects from the database or allowing for direct access to sensitive data.

- **Prevention**
  - Never rely on the client to filter data, and tailor API responses to the needs of the consumer. Ensure that there is a need-to-know for any PII returned
  - Ensure error responses do not expose sensitive information

##### Lack of Resource and Rate Limiting
-  **Definition**
<br/>
API is not protected against an excessive amount of calls or payload sizes. Attackers use that for DoS and brute force attacks.

- **Example**
<br/>
Attacker performs a DDoS or otherwise overwhelms the API.

- **Prevention**
  - Include rate limting, payload size limits, check compression ratios, and limit container resources

##### Broken Function Level Authorization
-  **Definition**
<br/>
API relies on client to use user level or admin level APIs. Attacker figures out the "hidden" admin API methods and invokes them directly.

- **Example**
<br/>
Administrative functions that are exposed to non-admin users.

- **Prevention**
  - Deny all access by default and build permissions from there based on specific roles
  - Test authorization through tools and manual testing

##### Mass Assignment
-  **Definition**
<br/>
The API takes data that client provides and stores it without proper filtering for allow-listed properties.

- **Example**
<br/>
Payload received from the client is blindly transformed into an object and stored.

- **Prevention**
  - Do not automatically bind incoming data without validating it first through an explicit list of parameters and payloads that you are expecting
  - Use a readOnly schema for properties that should never be modified
  - Enforce the defined schemas, types, and patterns that are accepted

##### Security Misconfiguration
-  **Definition**
<br/>
Poor configuration of the APIs servers allows attackers to exploit them.

- **Example**
<br/>
Numerous issues like unpatched systems, overexposed files and directories, missing or outdated configuration, exposed systems and unused features, verbose error messaging.

- **Prevention**
  - Use of hardened images and secure default configuration
  - Automation to detect (and repair) discovered misconfiguration
  - Disable unnecessary features, and limit admin access

##### Injection
-  **Definition**
<br/>
Attacker constructs API calls that include SQL-, NoSQL-, LDAP-, OS- and other commands that the API or backend behind it blindly executes.

- **Example**
<br/>
SQL, LDAP, OS, XML injection

- **Prevention**
  - Never trust end-user input
  - Have well-defined input data: schemas, types, string patters, etc.
  - Validate, filter, sanitize and quarantine (if needed) data from users

##### Improper Assets Management
-  **Definition**
<br/>
Attacker finds non-production versions of the API: such as staging, testing, beta or earlier versions - that are not as well protected and uses those to launch the attack.

- **Example**
<br/>
Backwards compatibility can leave legacy systems exposed. Old and non-production versions can be poorly maintained yet still have access to production data. These also allow for lateral movement in the system.

- **Prevention**
  - Properly inventory your systems and APIs
  - Limit access to anything that should not be public and properly segregate prod and non-prod environments
  - Implement security controls on the network and system such as API firewalls
  - Have a decommission process for old APIs and systems

##### Insufficent Logging and Monitoring
-  **Definition**
<br/>
Lack of proper logging, monitoring, and alerting let attacks go unnoticed.

- **Example**
<br/>
Logging and alerts go unnoticed or are not responded to. Logs are not protected against tampering and are not integrated into a centralized logging system like a SIEM.

- **Prevention**
  - Properly log sensitive workflows like failed login attempts, input validation failures, and failures in security policy checks
  - Ensure logs are formatted so that they can be imported in a centralized tool. Logs also need to be protected from tampering and exposure to unauthorized users
  - Integrate logs with monitoring and alerting tools

## Dive into OWASP Top 10

### Broken Access Control [# 1]
https://owasp.org/Top10/A01_2021-Broken_Access_Control/

- Authorization is the process where requests to access a resource should be granted or denied. It should be noted that authorization is not equivalent to authentication - as these terms and their definitions are frequently confused

- **Authentication** is providing and validating identity

- **Authorization** includes the execution rules that determines what functionality and data the user (or Principal) may access, ensuring the proper allocation of access rights after authentication is successful

- Having a license does not mean you are granted access to a military base. You have authentication, but not authorization

- **Access Control**
  ![Access Control](image/README/Access%20Control.PNG)
  
- **Common Vulnerabiltiies**
  - Violation of the principle of least privilege or deny by default, where access should only be granted for particular capabilities, roles, or users, but is available to anyone
  - Bypassing access control checks by modifying URL internal application state, or the HTML page, or simply using a custom API attack tool
  - Permitting viewing or editing someone else's account, by providing its unique idenitifier (insecure direct object references)
  - Accessing APIs that do not have proper access controls around HTTP verbs (PUT, POST, DELETE)
  - Elvation of privilege. Acting as a user without being logged in, or acting as an admin when logged in as a user
  - Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token or a cookie or hidden field manipulated to elevate privileges, or abusing JWT invalidation
  - CORS misconfiguration allows unauthorized API access
  - Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user. Accessing API with missing access controls for POST, PUT, and DELETE

- **Prevention**
  - Apart from public resources, deny by default
  - Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage
  - Model access controls should enforce record ownership, rather than accepting that the user can create, read, update or delete any record
  - Disable web server directory listing and ensure file metadata (e.g. git) and backup files are not present within web roots
  - Log access control failures, alert admins when appropriate (e.g. repeated failures)
  - Rate limit API and controller access to minimize the harm from automated attack tooling
  - JWT tokens should be invalidated on the server after logout

- **Example 1**
  - The application uses unverified data in a SQL call that is accessing account information:
  <pre>
    <code>
      pstmt.setString(I, request.getParameter("acct"));
      ResultSet results = pstmt.executeQuery();
    </code>
  </pre>  
  - An attacker simply modifies the 'acct' parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user's account (http://example.com/app/accountInfo?acct=notmyacct)

- **Example 2**
  - An attacker simply forces browser to target URLs. Admin rights are required for access to the admin page
  <pre>
    <code>
      http://example.com/app/getappInfo
      http://example.com/app/admin_getappInfo
    </code>
  </pre>
  - If an unauthenticated user can access either page, its a flaw. If a non-admin can access the admin page, this is a flaw

### Cryptographic Failures [# 2]
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

- **Data Protection**
  - **Protected Health Information (PHI)**
    <br/>
    Names, Dates, Phone/Fax Numbers, Email, SSN, MRN, Account Numbers, Biometric (finger, retinal, voice prints), Images 
  
  - **Personally Identifiable Information (PII)**
    <br/>
    Name, Address, Passport, Vehicle information, Drivers license, Credit card numbers, Digital identity, birthplace, genetic information, login name

  - **Sensitive Financial Information**
    <br/>
    Credit/Debit card numbers and security codes, Account numbers, loan agreements, loan details, Tax ID, PoS transactions

- **Cryptographic Failures**  
  ![Cryptographic Failures](image/README/Cryptograhic%20Failures.PNG)

- **Defense**
  ![Cryptographic Failures (Defense)](image/README/Cryptograhic%20Failures%20(Defense).PNG)

- **Example**
  - A site does not use or enforce TLS for all pages or supports weak encryption. An attacker monitors network traffic (e.g. at an insecure wireless network), downgrades connections from HTTPS to HTTP, intercepts requests and steals the user's session cookie. The attcker then replays this cookie and hijacks the user's (authenticated) session, accessing or modifying the user's private data. Instead of the above, they could alter all transported data (e.g. the recipient of a money transfer)


### Injection [# 3]
https://owasp.org/Top10/A03_2021-Injection/

- **Injection**
Anytime user input changes the intended behaviour of the system

- **How does it happen**
  - Trust of user input without validating, filtering, or sanitizing
  - Dynamic queries are used directly in an interpreter without escaping
  - Extracting additional information from by taking advantage weaknesses in search parameters used in object-relational mapping
  - Using input directly in a SQL command that is used for queries or commands

- **SQL Injection**
  - Allows attackers to manipulate SQL statements sent to a database from the web applicaiton
  - Exploits inadequate validation and sanitization of user-supplied input
  
- **SQL Injection Potential Impact**
  - Steal all data from the database
  - Access PII/PHI/PCI Data
  - Take over backend server or entire network
  - Remove data

- **Example (SQLI)**
An application uses untrusted data in the construction of the following vulnerable SQL call:
<pre>
  <code>
    String query = "SELECT \* FROM accounts WHERE custID = " + request.getParameter("id") + "";
  </code>
</pre>

Similarly, an application's blind trust in frameworks may result in queries that are still vulnerable (e.g. Hibernate Query Language (HQL))
<pre>
  <code>
    Query HQLQuery = session.createQuery("FROM accounts WHERE custID=" + request.getParamter("id") + "");
  </code>
</pre>

In both cases, the attacker modifies the "id" parameter value in their browser to send: ' or 'I'='I

For instance: http://example.com/app/accountView?id=' or 'I'='I

This changes the meaning of both queries to return all the records from the accounts table. More dangerous attacks could modify or delete data or even invoke stored procedures

- **Other Injection Flaws**
  - **OS Command**
    ![OS Injection](image/README/OS%20Injection.PNG)
    <br/>
    ![OS Injection (2)](image/README/OS%20Injection%20(2).PNG)
  - **LDAP**
    ![LDAP](image/README/LDAP.PNG)
  - **XPATH**
    ![XPATH](image/README/XPath.PNG)

- **Example**
  - http://example/defaul.aspx?user=*
  - In the example above, we send the * character in the user parameter which will result in the filter variable in the code to be initialized with (samAccountName=*)
  - The resulting LDAP statement will make the server return any object that contains the samAccountName attribute. In addition, the attacker can specify other attributes to search for and the page will return an object matching the query

- **Prevention**
  - Utilize a parametrized interface to the database
  - Positive server-side input validation (e.g. allow-list of valid input)
  - Escape special characters in the query flow
  - Limit the return of records in a query using SQL controls like LIMIT (record count)

### Insecure Design [# 4]
https://owasp.org/Top10/A04_2021-Insecure_Design/

- **Insecure Design**
  - Insecure design happens when we do not use secure design patterns 
  - Often thought of as security requirements/reference architecture when we do not have a paved road methodology (essentially placing secure guardrails around the development and deployment of application) that also leads us to insecure design
  - When we are not doing threat modeling (allows us identify threats and risks early on in the process and build in those requirements into the design early on), that also leads to insecure design

- **How to Prevent**
  - Establish and use a secure development lifecycle with AppSec professionals to help evaluate and design security and privacy-related controls
  - Establish and use a library of secure design patterns or paved road ready to use components
  - Use threat modeling for critical authentication, access control, business logic, and key flows
  - Integrate security language and controls into user stories
  - Integrate plausibility checks at each tier of your application (from frontend to backend)
  - Write unit and integration tests to validate that all critical flows are resistant to the threat model. Compile use-cases and misuse-cases for each tier of your application
  - Segregate tier layers on the system and network layers depending on the exposure and protection needs
  - Segregate tenants robustly by design throughout all tiers
  - Limit resource consumption by user or service

- **Defences**
  - Use a secure development lifecycle with security professionals for guidance
  - Create secure design patterns and architectures that can be reused to create a paved road
  - Threat model critical application workflows
  - Write secure unit and integration tests that use abuse and misuse cases
  - Design for segregation of tenants

- **Bad Bots**
  - A retail chain's e-commerce website does not have protection against bots run by scalpers buying high-end video cards to resell auction websites. This creates terrible publicity for the video card makers and retail chain owners and enduring bad blood with enthusiasts who cannot obtain these cards at any price. Careful anti-bot design and domain logic rules, such as purchases made within a few seconds of availability, might identify inauthentic purchases and rejected such transactions

### Security Misconfiguration [# 5]
https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

- **Absence of security settings in**
  - Application
  - Framework
  - Database
  - Web server
  - Platform

- **Lack of**
  - Patching
  - Secure settings for parsers
  - Outdated security configuration
  - Default settings/passwords
  - Overly verbose messaging when an error occurs
  - Out of date software

- **Defences**
  - Hardened secure defaults that are used to deploy in other environments in an automated method. Each environment should be configured identically with the same security controls
  - Reduce the extra features and frameworks that are not needed for used
  - Use a change management board to verify changes to environments and provide a gate for significant changes
  - Segment components and use automated tools to verify configuration and detect drift

- **Default settings in the cloud**
  - A cloud service provider (CSP) has default sharing permissions open to the Internet by other CSP users. This allows sensitive data stored within cloud storage to be accessed

### Using Known Vulnerable Components [# 6]
https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

- **Dependency**
  - Dependency is a broad software engineering term used to refer when a piece of software relies on another one
  
  ![Dependency](image/README/Dependency.PNG)

- **Vulnerable and Outdated Components**
  - The term "Components" in the title of this category refers to application frameworks, libraries or other software modules integrated into an application: such components are usually written by a 3rd Party but this is not exclusive
  - This category references using these components when they may have malicious code or security weaknesses within them (e.g. vulnerable)

- **Defences - Commercial**
  - Most applications include either commercial products or Open Source Software (OSS) within their software bundles
  - For commercial products, most major vendors such as Oracle, Google and IBM provide Security Bulletins to distribution lists for notification purposes. Make sure you are signed up for these services
  
- **Defences - Open Source Software**
  - For Open Source Software (OSS) libraries find a solution like Dependency Check, GitLab, or Jfrong, Xray, to automatically scan for vulnerable packages
  - Sign-up for regular security bulletins from the National Vulnerability Database (https://nvd.nist.gov/Home/Email-List) and regularly monitor components for security issues and updated versions

- **General Defence**
  - Do not give extreme trust in any 3rd party component
  - Always verify its size and checksum and download directly from vendor website, never a secondary party
  - Challenge the vendor to provide evidence of security vulnerability scanning. If possible, scan it yourself
  - Use well-known vendors and sources that are maintained 
  - Remove unnecessary components from your code if they are not in use

- **Example**
  - Components typically run with the same privileges as the application itself, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g. coding error) or intentional (e.g. a backdoor in a component) 
  - Some example exploitable component vulnerabilities discovered are:
    - CVE-2017-5638, a Struts 2 remote code execution vulnerability that enables the execution of arbitary code on the server, has been blamed for significant breaches
    - While the Internet of Things (IoT) is frequently difficult or impossible to patch, the importance of patching them can be great (e.g. biomedical devices)
  - There are automated tools to help attackers find unpatched or misconfigured systems. For example, the Shodan IoT search engine can help you find devices that still suffer from HeartBleed vulnerability patched in April 2014

- **Notification**
  - Have a means for receiving notifications on potentially vulnerable software
  - Many vendors like Microsoft already offer a notification service, however other services or feeds exist
  - Receiving notification is only part of the solution. You must also be able to:
    - Know where to patch (what systems or software are vulnerable)
    - Have the ability to test the new patch
    - Have a means to deliver the patch
    - Ability to notify those impacted by the changes to the system (users, customers, etc)
  
- **Patching Process**
![Patching Process](image/README/Patching%20Process.PNG)

### Identification and Authentication Failures [# 7]
https://owasp.org/Top10/A07_2021-Vulnerable_and_Outdated_Components/

- **How can Authentication be broken**
![Broken Authentication](image/README/Broken%20Authentication.PNG)

- **Attacks**
  - Password guessing attack (social engineering)
    - John from IT, needs your help ...
  - Dictionary attack
    - Dictionary words that are hashed and tested
  - Brute force attack
    - Guessing or targeted hashes
  - Username enumeration
    - Guessable patterns of usernames or log in failure messages that reveal too much
  - Phishing
    - Trick users into providing their credentials to an imposter, look-alike site

- **Account Recovery Risks**
  - Social Engineeing
    - Emailing a password reset form without using something like two factor
  - Easily guessable security answers
    - "What school did you attend"
  - Password sent through insecure channels
    - Email
  - Password change not required
    - Once you have been given a new password, it should be changed on the next login

### Software and Data Integrity Failures [# 8]
https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

- **Software Integrity Failures**
![Software Integrity Failures](image/README/Software%20Integrity%20Failures.PNG)

- **Software Integrity Prevention**
![Software Integrity Prevention](image/README/Software%20Integrity%20Prevention.PNG)

- **Example**
  - SolarWinds malicious update: Nation-states have been known to attack update mechanisms, with a recent notable attack being the SolarWinds Orion attack. The company that develops the software had secure build and update integrity processes. Still, these were able to be subverted, and for several months, the firm distributed a highly targeted malicious update to more than 18,000 organisations, of which around 100 or so were affected. This is one of the most far-reaching and most significant breaches of this nature in history

### Security Logging and Monitoring Failures [# 9]
https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/

- **Security Logging and Monitoring Failures**
  - Exploitation of insufficient logging and monitoring is the bedrock of nearly every major incident. Attackers rely on the lack of monitoring and timely response to achieve their goals without being detected
  - Most successful attacks start with vulnerability probing. Allowing such probes to continue can raise the likelihood of successful exploit to nearly 100%
  - Between October 1, 2020, through December 31, 2021, the median number of days between compromise and detection was 21, down from 24 days in 2020 (itbrew.com)
    - In 2016, identifying a breach took an average of 191 days
  - Insufficient logging, detection, monitoring and active response occurs any time:
    - Auditable events, such as logins, failed logins, and high-value transactions are not logged
    - Warnings and errors generate no, inadequate or unclear log messages
    - Logs of applications and APIs are not monitored for suspicious activity or logs are only stored locally
    - Appropriate alerting thresholds and response escalation processes are not in place or effective
    - Penetration testing and scans by DAST tools (such as OWASP ZAP) do not trigger alerts
    - The application is unable to detect, escalate, or alert for active attacks in real time or near real time
    - Plans for monitoring, and response should be developed and well known to the organisation


- **Good Practices**
  - As per the risk of the data stored or processed by the application:
    - Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis
    - Ensure that logs are generated in a format that can be easily consumed by a centralized log management solutions
    - Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar
    - Establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion
    - Establish or adopt an incident response and recovery plan

- **SIEM (Security Information and Event Management)**
![SIEM](image/README/SIEM.PNG)

### Server-Side Request Forgery (SSRF) [# 10]
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/

- **SSRF occurs when we do not**
![SSRF](image/README/SSRF.PNG)

- **Defenses**
  - From Network Layer
    - Segment remote resource access functionality in separate networks to reduce the impact of SSRF
    - Enforce "deny by default" firewall policies or network access control rules to block all but essential intranet traffic

  - From Application Layer
    - Sanitize and validate all client-supplied input data
    - Enforce the URL schema, port, and destination with a positive allow list
    - Do not send raw responses to clients
    - Disable HTTP redirections
    - Be aware of the URL consistency to avoid attacks such as DNS rebinding and "time of check, time of use" (TOCTOU) race conditions

- **Example**
  - Sensitive data exposure
    - Attackers can access local files or internal services to gain sensitive information such as file:///etc/passwd</span> and http://localhost:28017/

  - Compromise internal services
    - The attacker can abuse internal services to conduct further attacks such as Remote Code Execution (RCE) or Denial of Service (Do)

## Defense and Tools

### Cross Site Scripting 
- **Cross Site Scripting (XSS)**
  - Is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy
  - This subversion is possible because the web application fails to properly validate input from the web browser (e.g. client) and/or fails to properly escape that input in the response

  ![Cross-Site Scripting](image/README/Cross-Site%20Scripting.PNG)

  ![Cross-Site Scripting (2)](image/README/Cross-Site%20Scripting%20(2).PNG)

### Content Security Policy (CSP)
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

- **Content Security Policy (CSP)**
  - Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks
  - To enable CSP, you need to configure your web server to return the Content-Security-Policy HTTP header
  - Browsers that do not support it will work with servers that implement it and vice versa; browsers that do not support CSP simply ignore it, functioning as usual, defaulting to the standard same-origin policy for web content
  
- **Mitigating XXS**
  - CSP makes it possible server administrators to reduce or eliminate the vectors by which XSS can occur by specifying the domains that the browser should consider to be valid sources of executable scripts
  - A CSP compatible browser will then only execute scripts loaded in source files received from those whitelisted domains, ignoring all other script (including inline scripts and event-handling HTML attributes)
  - As an ultimate form of protection, sites that want to never allow scripts to be executed can opt to globally disallow script execution

- **Writing a Policy**
  - A policy is described using a series of policy directives, each of which describes the policy for a certain resource type of policy area
  - A policy needs to include a default-sec or script-src directive to prevent inline scripts from running, as well as blocking the use of eval()
  - Your policy should include a default-src policy directive, which is a fallback for other resource types when they do not have policies of their own
  - A policy needs to include a default-src or style-src directive to restrict inline styles from being applied from a `<style>` element or a style attribute

- **Directives CSP 1.0**
  - **connect-src** (d)
    <br/>
    restricts which URLs the protected resource can load using script interfaces (e.g. send() method of an XMLHttpRequest object)

  - **font-src** (d)
    <br/>
    restricts from where the protected resource can load fonts

  - **img-src** (d)
    <br/>
    restricts from where the protected resource can load images

  - **media-src** (d)
    <br/>
    restricts from where the protected resource can load video, audio, and associated text tracks

  - **object-src** (d)
    <br/>
    restricts from where the protected resource can load plugins

  - **script-src** (d)
    <br/> 
    restricts which scripts the protected resource can execute. Additional restrictions against inline scripts and eval. Additional directives in CSP2 for hash and nonce support

  - **style-src** (d)
    <br/>
    restricts which styles the user may applies to the protected resource. Additional restrictions against inline and eval

  - **default-src** (d)
    <br/>
    covers any directive with

  - **frame-src**
    <br/> 
    restricts from where the protected resource can embed frames. Note, deprecated in CSP2

  - **report-url**
    <br/>
    specifies a URL to which the user agent sends reports about policy violation

  - **sandbox**
    <br/>
    specifies an HTML sandbox policy that the user agent applies to the protected resource. Optional in 1.0

- **Directives CSP 2.0**
  - **form-action**
    <br/>
    restricts which URLs can be used as the action of HTML form elements 

  - **frame-ancestors**
    <br/>
    indicates whether the user agent should allow embedding the resource using a frame, iframe, object, embed or applet element or equivalent functionality in non-HTML resources
  
  - **plugin-types**
    <br/>
    restricts the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded
  
  - **base-uri**
    <br/>
    restricts the URLs that can be used to specify the document URL

  - **child-src** (d)
    <br/>
    governs the creation of nested browsing contexts as well as Worker execution contexts

- **Sample**
![CSP Sample](../../../Downloads/CSP%20Sample.PNG)

### Security Models
- **Security Models**
  - Security models are used to understand the systems and processes developed to enforce security principles
  - Three key elements play a role in systems with respect to model implementation: People, Processes, Technology
  - Addressing a single element of the three may provide benefits, but more effectiveness can be achieved through addressing multiple elements
  - How security models are used in an OS design:
    <br/>
    ![Security Model](image/README/Security%20Model.PNG)

- **Access Control Models**
  - **Access Control List (ACL)**
    <br/> 
    A list of permissions attached to an object. An ACL specifies which users or system processes are granted access to objects, as well as what operations are allowed on given objects
  
  - **Bell-LaPadula model**
    <br/>
    The model is a formal state transition model of computer security policy that describes a set of access control rules which use security labels on objects and clearances for subjects. Security labels range from the most sensitive (e.g. "Top Secret"), down to the least sensitive (e.g. "Unclassified" or "Public")

  - **Role-based Access Control**
    <br/>
    Role-based access control (RBAC) is a policy-neutral access-control mechanism defined around roles and privileges. The components of RBAC such as role-permissions, user-role and role-role relationships make it simple to perform user assignments
  
  - **Access-based Access Control**
    <br/>
    Also known as policy-based access control, defines an access control paradigm whereby access rights are granted to users through the use of policies which combine attributes together. The policies can use any type of attributes (user attributes, resource attributes, object, environment attributes, etc.) This model supports Boolean logic, in which rules contain "IF, THEN" statements about who is making the request, the resource and the action

- **Multi-level Security Model - Integrity Model**
  - **Biba Integrity Model**
    <br/>
    The model is designed so that subjects may not corrupt data in a level ranked higher than the subject, or be corrupted by data from a lower level than the subject. In the Biba model, users can only create content at or below their own integrity level (a monk may write a prayer book that can be read by commoners, but not one to be read by a high priest) Conversely, users can only view content at or above their own integrity level (a monk may read a book written by the high priest, but may not read a pamphlet written by a lowly commoner)

  - **Clark-Wilson Model**
    <br/>
    Instead of defining a formal state machine, the model defines each data item and allows modifications thorugh only a small set of programs. The model uses a three-part relationship of subject/program/object (where program is interchangeable with transaction) known as a triple or an access control triple. Within this relationship, subjects do not have direct access to objects. Objects can only be accessed through programs

- **Multi-level Security Model - Information Flow Model**
  - **Brewer-Nash Model (Chinese Wall)**
    <br/>
    Technology can be employed to prevent access to data by conflicting groups. People can be trained not to compromise the separation of information. Policies can be put in place to ensure that the technology and the actions of personnel are properly engaged to prevent compromise

  - **Data Flow Diagrams**
    <br/>
    Specifically designed to document the storage, movement and processing of data in a system. They are constructed on a series of levels. The highest level, level 0, is a high-level contextual view of the data flow through the system. The next level, level 1, is created by expanding elements of the level 0 diagram. This level can be exploded further to a level 2 diagram, or the lowest-level diagram of a system

  - **Use Case Models**
    <br/>
    Requirements from the behavioral perspective provide a description of how the system utilizes data. Use cases are constructed to demonstrate how the system processes data for each of its defined functions

  - **Assurance Models**
    <br/>
    The level of confidence that software is free from vulnerabilities, either intentionally designed into the software or accidentally inserted at any time during its lifecycle, and that software functions in the intended manner

### Software Composition Analysis (SCA)
- **Software Composition Analysis (SCA)**
  - SCA is the process of validating that the components, libraries and opensource software that is used in an application is free from known vulnerabilities and license compliance
  - These external software components can come from several places:
    - Downloads
    - Commercial applications
    - Third-party libraries and software
    - From outsource development by consulting

  - SCA can provide:
    - Component tracking and inventory
    - Vulnerability identification and remediation recommendation
    - License management
   
  ![SCA](image/README/SCA.PNG)

- **OWASP Dependency Check**
  - .NET and Java compatible, Dependency Check is used to scan libraries used as build dependencies during the build process
  - Dependencies are matched against the NVD (National Vulnerability Database) to determine whether the dependency being used is vulnerable
  - A report is generated and can be used to identify the dependencies as well as understand the mitigation (In mos t cases, the mitigation is to use the most up to date level of software)

- **National Vulnerability Database**
https://nvd.nist.gov/

  - The NVD is the U.S government repository of standards based vulnerability mmanagement data represented using Security Content Automation Protocol (SCAP) This data enables automation of vulnerability management, security measurement, and compliance
  - The NVD includes databases of security checklist references, security related software flaws, misconfigurations, product names and impact metrics
  
![NVD](image/README/NVD.PNG)

- **Sample**
![Dependency Check](image/README/Dependency%20Check.PNG)

- **JFrog Xray**
![JFrog](image/README/JFrog.PNG)
![JFrog Xray](image/README/JFrog%20Xray.PNG)

### Security Knowledge Framework
- **Security Knowledge Framework (SKF)**
  - The OWASP Security Knowledge Framework is intended to be a tool that is used as a guide for building and verifying secure software
  - Education is the first step in the Secure Software Development Life Cycle
  - "The OWASP Security Knowledge Framework is an expert system web-application that uses the OWASP Application Security Verification Standard and other resources. It can be used to support developers in pre-development (security by design) as well as after code is released (OWASP ASVS 
  - Level 1-3)"

- **Why**
  - Security by design
  - Information is hard to find
  - Examples lack security details
  - Security is hard
  - Together we can create secure web applications
  - Defensive coaching approach
  - SKF is the first step in SDLC

- **How SKF can be used**
  - Security Requirements OWASP ASVS for development and for third party vendor applications
  - Security knowledge reference (Code examples/Knowledge Base items)
  - Security is part of design with the pre-development functionality in SKF
  - Security post-development functionality in SKF for verification with the OWASP ASVS

- **Stages of Development**
  - **Pre development stage**
    <br/>
    Here we detect threats beforehand and we provide developers with secure development patterns as well as providing feedback and solutions on how to handle their threats

  - **Post development stage**
    <br/>
    By means of checklists, we guide developers through a process where we harden their application infrastructure and functions by providing feedback and solutions

- **References**
  - Link
    <br/>
    https://www.owasp.org/index.php/OWASP_Security_Knowledge_Framework
  - Video
    <br/>
    https://www.youtube.com/watch?v=_XS9gr5OAwc
  - Demo Site 
    <br/>
    https://demo.securityknowledgeframwork.org/

### Secure Code Review
- **Who to include**
  - Like threat modeling, you want to have the appropriate members involved in the review:
    - Developers
    - Architects
    - Security SME (Subject Matter Expert)
    - Depending on the portion of the application you may need to include the SME for that topic (Authentication, DB logic, User Experience ...)
  
- **Scope and Aid**
1. Code reviews should take into consideration the threat model and high-risk transactions in the application
2. A completed threat model will highlight the areas of concern
3. Any time code is added/updated in those high-risk areas a code review should include a security component
4. When changes are required to the threat model due to findings during that code review, the threat model should be updated

- **Understand the risk**
  <br/>
  ![Understand the risk](image/README/Understand%20the%20risk.PNG)

  - When considering the risk of code under review, consider some common criteria for establishing risk of a particular code module. The higher the risk, the more thorough the review should be
    - Application features and business logic
    - Context/Sensitive Data
    - The code (language, feature, nuance of language)
    - User roles and access rights (anonymous access?)
    - Application type (mobile, desktop, Web)
    - Design and architecture of the application
    - Company standards, guidelines and requirements that apply

  - The reviewer will need certain information about the development in order to be effective
    - Design documents, business requirements, functional specifications, test results and the like
    
  - If the reviewer is not part of the development team, they need to talk with developers and the lead architect for the application and get a sense of the application
    - Does not have to be a long meeting, it could be a whiteboard session for the development team to share some basic information about the key security considerations and controls

- **Information Gathering Tips**
  - Walkthrough of the actual running application
  - A brief overview of the structure of the code base and any libraries
  - Knowing the architecture of the application goes a long way in understanding the security threats that are applicable
    - Tech Stack, deployment, users and data
  - All the required information of the proposed design including flow charts, sequence diagrams, class diagrams and requirements documents to understand the objective of the proposed design should be used as reference during the review

- **Performing the review (using the checklist)**
  - When using the Code Review Checklist Template, the reviewer may filter out non-applicable categories
  - It is recommended that the complete list is used for code that is high risk. For instance, code that impacts patient safety workflows or mission critical functionality shall use the complete code review list
  - The code review template should be completed and appended during code check-in in the code repository or with the completed code review using a tool (Crucible)
  
- **When to perform the review**
  - **Code**
    <br/>
    Pre-commit: Code review during pre-commit means that dangerous or sub-par code does not make it to the code branch. However, this does reduce the time to delivery of new code

  - **Post**
    <br/> 
    Post-commit: This allows for faster delivery of software but runs the risk of allowing dangerous code into the branch. Other developers may also add their code which can make future reviews more cumbersome

  - **Audit**
    <br/>
    During a code audit: This can be triggered by an event such as a found vulnerability and should review the entire area of concern rather than focus on a single code commit

- **What to do with results**
  <br/>
  A vulnerability or risk found during a code review should be addressed immediately if found in the pre-commit phase. However, there may be cases when code cannot be mitigated, or issues are found after code has been committed. In those cases, go through a Risk Rating to determine its impact and undestand the timeframe for remediation.

- **OWASP Secure Code Review**
  - https://owasp.org/SecureCodingDogo/codereview101/
  - https://owasp.org/images/5/53/OWASP_Code_Review_Guide_v2.pdf

## Session Management

### Introduction to Session Management
- **Sessions**
  - A web session is a sequence of network HTTP request and response transactions associated to the same user
  - Modern and complex web applications require the retaining of information or status about each user for the duration of multiple requests
  - Sessions provide the ability to establish variables (such as access rights and localization settings) which will apply to each and every interaction a user has with the web application for the duration of the session

 Web applications can create sessions to keep track of anonymous users after the very first user request
  -  An example would be maintaining the user language preference
  
Additionally, web applications will make use of sessions once the user has authenticated
  - This ensures the ability to identify the user on any subsequent requests as well as being able to apply security access controls, authorized access to the user private data, and to increase the usability of the application
 
Therefore, current web applications can provide session capabilities **both pre and post authentication**

Once an authenticated session has been established, the session ID (or token) is temporarily equivalent to the strongest authentication method used by the application
  - such as username and password, passphrases, one-time passwords (OTP), client-based digital certificates, smartcards, or biometrics (such as fingerprint or eye retina)

HTTP is a stateless protocol where each request and response pair is independent of other web interactions.

Session management links both the authentication and authorization modules commonly available in web applications:
- The session ID or token binds the user authentication credentials to the user HTTP traffic and the appropriate access controls enforced by the web application
- The complexity of these components in modern web applications, plus the fact that its implementation and binding resides on the web developer's hands makes the implementation of a secure session management module very challenging

![Session Management](image/README/Session%20Management.PNG)

- Since HTTP and Web Server both are stateless, the only way to maintain a session is when some unique information about the session (session id) is passed between server and client in every request and response
- Methods of Session Management:
  - **User Authentication**
    <br/>
    Common for a user to provide authentication credentials from the login page and then the authentication information is passed between server and client to maintain the session

  - **HTML Hidden Field**
    <br/>
    A unique hidden field in the HTML and when user starts navigating, we can set its value unique to the user and keep track of the session

  - **URL Rewriting**
    <br/>
    A session identifier parameter is appended to every request and response to keep track of the session

  - **Cookies**
    <br/>
    Cookies are small piece of information that are sent by the web server in the response header and gets stored in the browser cookies. When client make further request, it adds the cookie to the request header to keep track of the session

- **Federated Identity**
1. A federated identity in information technology is the means of linking a person's electronic identity and attributes, stored across multiple distinct **identity management** systems
2. Federated identity is related to single sign-on (SSO), in which a user's single authentication ticket, or token, is trusted across multiple IT systems or even organisations
3. The "federation" of identity describes the technologies, standards and use-cases which serve to enable the portability of identity information across otherwise autonomous security domains
   - Technologies:
     - Security Assertion Markup Language (SAML)
     - OAuth
     - OpenID
     - Security Tokens (Simple Web Tokens, JSON Web Tokens and SAML assertions)
     - Web Service Specifications and Windows Identity Foundation

![Federated Identity](image/README/Federated%20Identity.PNG)

<hr/>

### Web Server Session Management

- **Java Session Management (Cookies)**
![Java Session Management](image/README/Java%20Session%20Management.PNG)

- **Java Session Management (HTTPSession)**
 - Servlet API provides Session management through HttpSession interface. We can get session from HttpServletRequest object using following methods. HttpSession allows us to set objects as attributes that can be retrieved in future requests.
   - HttpSession getSession()
      <br/>
      This method always returns a HttpSession object. It returns the session object attached with the request, if the request has no session attached, then it creates a new session and return it

   - HttpSession getSession(boolean flag)
      <br/>
      This method returns HttpSession object if request has session else it returns null

  - When HttpServletRequest getSession() does not return an active session, then it creates the new HttpSession object and adds a Cookie to the response obejct with name JSESSIONID and value as session id
  - This cookie is used to identify the HttpSession object in further requests from client

- **Java Session Management (URL Rewrite)**
  - There may be times where the browser has cookies disabled
  - The application may choose to pass session information in the URL
  - The URL can be encoded with HttpServletResponse encodeURL() method
    - In a redirect the request to another resource can be encoded with encodeRedirectURL() method
  - **However**: there is a clear security concern with the session in the URL

- **.NET Sessions Management**
  <br/>
  ![.NET Session Management](image/README/.NET%20Session%20Management.PNG)   

- .NET session state supports several different storage options for session data. Each option is identified by a value in the SessionStateMode enumeration. The following list describes the available session state modes:
  - You can specify which mode you want .NET session state to use by assigning a SessionStateMode enumeration values to the **mode** attribute of the sessionState element in your application's Web.config file. Modes other than **InProc** and **Off** require additional parameters, such as connection-string values
  - **InProc** mode, which stores session state in memory on the Web server. This is the default
  - **StateServer** mode is a somewhat slower service than the in-process variant since calls go to another server. All session data is stored in memory of the State Machine
  - **SQLServer** mode stores session state in a SQL Server database ensuring that session is maintained after an application is restarted and can be shared in a farm
  - **Custom** mode, which enables you to specify a custom storage provider
  - **Off** mode, which disables session state

- **In-Process**
  - **In-process** mode is the default session state mode and is specified using the InProc SessionStateMode enumeration value
  - In-process mode stores session state values and variables in memory on the local Web server
  - It is the only mode that supports the Session_OnEnd event
  - The Session_OnEnd event occurs when a session is abandoned or times out

- **State Server Mode**
  - **StateServer** mode stores session state in a process, referred to as the ASP.NET state service, that is separate from the ASP.NET worker process or IIS application pool. Using this mode ensures that session state is preserved if the Web application is restarted and also makes session state available to multiple Web servers in a Web farm
  - To improve the security of your application when using StateServer mode, it is recommended that you protect your stateConnectionString value by encrypting the sessionState section of your configuration file
  <pre>
    <code>
      <sessionState mode="StateServer" stateConnectionString="tcpip=SampleStateServer:42424" cookieless="false" timeout="20"/>
    </code>
  </pre> 

- **SQL Server Mode**
  - **SQLServer** mode stores session state in a SQL Server database. Using this mode ensures that session state is preserved if the Web application is restarted and also makes session state available to multiple Web servers in a Web farm
  - To use SQLServer mode, you must first be sure the ASP.NET session state database is installed on SQL Server
  <pre>
    <code>
      <sessionState mode="SQLServer" sqlConnectionString="Integrated Security=SSPI;datasource=SampleSqlServer;"/>
    </code>
  </pre> 

- **Custom Mode**
  - **Custom** mode specifies that you want to store session state data using a custom session state store provider. When you configure your .NET application with a Mode of Custom, you must specify the type of the session state store provider using the providers sub-element of the sessionState configuration element. You specify the provider type using an add sub-element and include both a type attribute that specifies the provider's type name and a name attribute that specifies the provider instance name
  <pre>
    <code>
      <providers>
        <add name="OdbcSessionProvider" type="Samples.AspNet.Session.OdbcSessionStateStore" connectionStringName="OdbcSessionServices" writeExceptionsToEventLog="false" />
      </providers>
    </code>
  </pre> 

<hr/>

### JWT JSON Web Token
https://jwt.io/

- **JSON Web Token (JWT)**
  - JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object
  - This information can be verified and trusted because it is digitally signed 
    - JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA
  - Although JWTs can be encrypted to also provide secrecy between parties
    - Signed tokens can verify the integrity of the claims contained within it, while encrypted tokens hide those claims from other parties
    - When tokens are signed using public/private key pairs, the signature also certifies that only the party holding the private key is the one that signed it

- **Use Cases**
  - **Authorization**
    <br/>
    This is the most common scenario for using JWT. Once the user is logged in, each subsequent request will include the JWT, allowing the user to access routes, services, and resources that are permitted with that token

  - **Information Exchange**
    <br/>
    JSON Web Tokens are a good way of securely transmitting information between parties
      - Signed tokens - confirm senders are who they say they are
      - Hashed - verified that the content has not been tampered with

- **How it works**
  <br/>
  In authentication, when the user successfully logs in using his credentials, a JSON Web Token will be returned and must be saved locally instead of the traditional approach of creating a session in the server and returning a cookie
  <br/>
  Whenever the user wants to access a protected route, it should send the JWT, typically in the Authorization header using the Bearer schema
  <br/>
  This is a stateless authentication mechanism as the user state is never saved in the server memory. The server's protected routes will check for a valid JWT in the Authorization header, and if there is, the user will be allowed
  <br/>
  As JWTs are self-contained, all the necessary information is there, reducing the need of going back and forward to the database
  <br/>
  ![JWT](image/README/JWT.PNG)

- **Structure**
  <br/>
  In its compact form, JSON Web Token consist of three parts separated by dots(.) which are:
  - **Header**
    <br/>
    The header typically consists of two parts: the type of token (JWT) and the hashing algorithm being used (such as HMAC, SHA256 or RSA)
    - Example
      <br/>  
      ![JWT (Header)](image/README/JWT%20(Header).PNG)   

  - **Payload**
    <br/>
    The second part of the token is the payload, which contains the claims. **Claims are statements about an entity** (typically, the user) and additional data. There are three types of claims: 
    - **Registered claims**
      <br/>
      These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Some of them are: iss(issuer), exp (expiration time), sub (subject), aud (audience) and others

    - **Public claims**
      <br/>
      These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace

    - **Private claims**
      <br/>
      These can the custom claims created to share information between parties that agree on using them and are neither registered or public claims

    - Example
      <br/>
      ![JWT (Payload)](image/README/JWT%20(Payload).PNG)

  - **Signature**
    <br/>
    To create the signature part, you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that

    - Example
      <br/>
      ![JWT (Signature)](image/README/JWT%20(Signature).PNG)

Therefore, a JWT typically looks like the following.
<br/>
(xxxxx.yyyyy.zzzzz)

<hr/>

### OAuth
https://oauth.net/

- **OAuth**
  - OAuth is an open standard for **access delegation**, commonly used as a way for Internet users to grant websites or applications access to their information on other websites but without giving them the passwords
  - This mechanism is used by companies such as Amazon, Google, Facebook, Microsoft and Twitter to permit the users to share information about their accounts with third party applications or websites
  ![OAuth (Social Media)](image/README/OAuth%20(Social%20Media).PNG)
  - OAuth decouples authentication from authorization and supports multiple use cases addressing different device capabilities. It supports server-to-server apps, browser-based apps, mobile/native apps, and consoles/TVs
  - OAuth is a delegated authorization framework for REST/APIs. It enables apps to obtain limited access (scopes) to a user's data without giving away a user's password
  - Designed specifically to work with HTTP, OAuth essentially allows access tokens to be issued to third-party clients by an authorization server, with the approval of the resource owner. The third party then uses the access token to access the protected resources hosted by the resource server

- **OAuth Actors**
![OAuth Actors](image/README/OAuth%20Actors.PNG)

- **OAuth Scopes**
![OAuth Scopes](image/README/OAuth%20Scopes.PNG)

- **OAuth Tokens**
  - Access tokens are the token the client uses to access the Resource Server (API). They are meant to be short-lived. Think of them in hours and minutes, not days and month. Because these tokens can be short lived and scale out, they cannot be revoked, you just have to wait for them to time out
  - The other token is the refresh token. This is much longer-lived; days, months, years. This can be used to get new tokens and can be revoked to kill an applications access
  - The OAuth spec does not define what a token is. It can be in whatever format you want. Usually though, you want these tokens to be JSON Web Tokens

  Tokens are retrieved from endpoints on the authorization server.
    - The authorize endpoint is where you go to get consent and authorization from the user
    - The token endpoint provides the refresh token and access token

  You can use the access token to get access to APIs. Once it expires, you will have to go back to the token endpoint with the refresh token to get a new access token.
  ![OAuth](image/README/OAuth.PNG)
  ![OAuth (2)](image/README/OAuth%20(2).PNG)

<hr/>

### Open ID
- **OpenID 1.0 and 2.0**
  - OpenID is an open standard and decentralized authentication protocol promoted by the non-profit OpenID Foundation
    - It allows users to be authenticated by co-operating sites (known as relying parties, or RP) using a third-party service, eliminating the need for webmasters to provide their own ad hoc login systems, and allowing users to log into multiple unrelated websites without having to have a separate identity and password for each
  - The OpenID standard provides a framework for the communication that must take place between the identity provider and the OpenID acceptor (the "relying party")
  - The OpenID protocol does not rely on a central authority to authenticate a user's identity
    - Neither services nor the OpenID standard may mandate a specific means by which to authenticate users, allowing for approaches ranging from the common (such as passwords) to the novel (such as smart cards or biometrics)

- **OpenID**
<br/>
https://openid.net/

OpenID allows you to use an existing account to sign into multiple websites, without needing to create new passwords
<br/><br/>
You may choose to associate information with your OpenID that can be shared with the websites you visit, such as a name or email address
<br/><br/>
With OpenID, your password is only given to your identity provider, and that provider then confirms your identity to the websites you visit. Other than your provider, no website ever sees your password

- **OpenID Authentication**
The end-user interacts with a relying party (such as website) that provides an option to specify an OpenID for purposes of authentication
<br/><br/>
The relying party and the OpenID provider establish a shared secret, which the relying party then stores
<br/><br/>
The relying party redirects the end-user's user-agent to the OpenID provider so the end-user can authenticate directly with the OpenID provider
<br/><br/>
If the end-user accepts the OpenID provider's request to trust the relying party, then the user-agent is redirected back to the relying party

![OpenID Authentication](image/README/OpenID%20Authentication.PNG)

- **OAuth and OpenID Connect**
<br/>
OAuth is directly related to OpenID Connect (OIDC) since OIDC is an authentication layer built on top of OAuth 2.0. OAuth is also distinct from XACML, which is an authentication policy standard
<br/><br/>
OAuth can be used in conjunction with XACML where OAuth is used for ownership consent and access delegation whereas XACML is used to define the authorization policies (e.g. managers can view documents in their region)

- **OpenID Connect**
https://developers.google.com/identity/protocols/oauth2/openid-connect

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol
<br/><br/>
It allows Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner
<br/><br/>
OpenID Connect allows clients of all types, including Web-based, mobile and JavaScript clients, to request and receive information about authenicated sessions and end-users
<br/><br/>
The specification suite is extensible, allowing participants to use optional features such as encryption of identity data, discovery of OpenID Providers, and session management, when it makes sense for them

![OpenID Connect](image/README/OpenID%20Connect.PNG)

## Risk Rating Methodologies 
https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

- **When and Why do we risk rate**
  - Risk Rating should be completed when there is a finding from a review of the application architecture/design from threat modeling, through a code review, or a penetration test
  - The goal of risk rating is to identity the risk to the system and business in order to put a plan in place to address the risk through prioritization

- **OWASP Risk Rating**
<br/>
RISK = LIKELIHOOD * IMPACT

- **Risk Rating Method**
![Risk Rating Method](image/README/Risk%20Rating%20Method.PNG)

  **1. Identify a risk**
  <br/>
  The first step is to identify a security risk that needs to be rated. The tester needs to gather information about the threat agent involved, the attack that will be used, the vulnerability involved, and the impact of a successful exploit on the business

  **2. Estimating Likelihood**
  <br/>
  Once the tester has identified a potential risk and wants to figure out how serious it is, the first step is to estimate the "likelihood". At the highest level, this is a rough measure of how likely this vulnerability is to be uncovered and exploited by an attacker
  <br/><br/>
  Here you are using the **Threat Agent Factors** and **Vulnerability Factors**

  - Factors
    - **Threat agent**
      <br/>
      The goal here is to estimate the likelihood of a successful attack by this group of threat agents. Use the worst-case threat agent
        - Skill Level (How technically skilled is this group of threat agents?)
        - Motive (How motivated is this group of threat agents to find and exploit this vulnerability?)
        - Opportunity (What resources and opportunities are required for this group of threat agents to find and exploit this vulnerability?)
        - Size (How large is this group of threat agents?)
    
    - **Vulnerability**
       <br/>
      The goal here is to estimate the likelihood of the particular vulnerability involved being discovered and exploited. Assume the threat agent selected above.
        - Ease of Discovery (How easy is it for this group of threat agents to discover this vulnerability?)
        - Ease of Exploit (How easy is it for this group of threat agents to actually exploit this vulnerability?)
        - Awareness (How well known is this vulnerability to this group of threat agents?)
        - Intrusion Detection (How likely is an exploit to be detected?)

  **3. Estimating Impact**
  <br/>
  When considering the impact of a successful attack, it is important to realize that there are two kinds of impacts. The first is the "**technical impact**" on the application, the data it uses, and the functions it provides. The other is the "**business impact**" on the business and company operating the application

  - Factors
    - **Technical Impact**
    <br/>
    Technical impact can be broken down into factors aligned with the traditonal security areas of concern: confidentiality, integrity, availability and accountability. The goal is to estimate the magnitude of the impact **on the system** if the vulnerability were to be exploited
      - Loss of confidentiality (How much data could be disclosed and how sensitive is it?)
      - Loss of integrity (How much data could be corrupted and how damaged is it?)
      - Loss of availability (How much service could be lost and how vital is it?)
      - Loss of accountability (Are the threat agents' actions traceable to an individual?)

    - **Business Impact**
    <br/>
    Business impact stems from the technical impact but requires a deep understanding of **what is important to the company running the application**. In general, you should be aiming to support your risks with business impact, particularly if your audience is executive level. The business risk is what justifies investment in fixing security problems
      - Financial damage (How much financial damage will result from an exploit?)
      - Reputation damage (Would an exploit result in reputation damage that would harm the business?)
      - Non-compliance (How much exposure does non-compliance introduce?)
      - Privacy violation (How much personally identifiable information could be disclosed?)

  **4. Determine the severity of the risk**
  <br/>
  In this step the likelihood estimate and the impact estimate are put together to calculate an overall severity for this risk. This is done by figuring out whether the likelihood is low, medium or high and then do the same for impact

  - **Informal**
    <br/>
    In many environments, there is nothing wrong with reviewing the factors and simply capturing the answers. The tester should think through the factors and identify the key "driving" factors that are controlling the result

  - **Repeatable**
    <br/>
    If it is necessary to defend the ratings or make them repeatable, then it is necessary to go through a more formal process of rating the factors and calculating the result

  - Sample
  ![Determine severity of risk](image/README/Determine%20severity%20of%20risk.PNG)

  ![Determine severity of risk (2)](image/README/Determine%20severity%20of%20risk%20(2).PNG)

  **5. Deciding what to fix**
  <br/>
  After the risks to the application have been classified, there will be a prioritized list of what to fix. As a general rules, the most severe risks should be fixed first. It simply does not help the overall risk profile to fix less important risks, even if they are easy or cheap to fix
  <br/><br/>
  Remember that not all risks are worth fixing, and some loss is not only expected, but justifiable based upon the cost of fixing the issue. For example, if it would cost $100,000 to implement controls to stem $2,000 fraud per year, it would take 50 years return on investment to stamp out the loss. But remember there may be reputation damage from the fraud that could cost the organisation much more

  - **Handling risk**
    - **Accept**
      <br/>
      Document the risk, acknowledge it and assign ownership

    - **Avoid**
      <br/>
      Place other controls that will reduce or eliminate the risk

    - **Mitigate**
      <br/>
      Fix the issue that exposes you to risk
      
    - **Transfer**
      <br/>
      If you are practically unable to deal with a risk, you may contractually obligate someone else to accept the risk

  - **Threat Mitigation Examples**
  ![Threat Mitigation Examples](image/README/Threat%20Mitigation%20Examples.PNG)
      
  - **Which one to use**
  ![Which one to use](image/README/Which%20one%20to%20use.PNG)

<hr/>

### Threat Modeling
Threat Modeling is a structured approach to identify, quantify, and address the security threats and risks associated with an application
<br/>
Threat modeling is an investigative technique for identifying application security risks/hazards that are technical (and even implementation specific)

