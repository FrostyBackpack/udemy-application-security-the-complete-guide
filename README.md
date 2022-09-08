# Objectives

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

- Asset
    <br/>
    An **asset** is anything you deem to have **value**
    <br/>
    An asset may be valuable because:
  - It <u>holds</u> its value (E.g. gold/diamonds)
  - It <u>produces</u> value (E.g. Technology space, a server in a data center - running applications produce value to organization)
  - It <u>provides access</u> to value (E.g. a PIN number to a bank account to get money - something that needs to be protected)

- Vulnerability
    <br/>
    A vulnerability is any weakness in an asset that makes it susceptible to attack of failure

- Attack
    <br/>
    An attack is any <u>intentional</u> action that can reduce the value of an asset
    <br/>
    E.g. An attacker might perform a DDoS attack on that web server to reduce value for organisation intentionally

- Failures + Errors
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

- Confidentiality
    <br/>
    Information is only available to those who should have access (we can do this through encryption and HTTPS when we talking about browser traffic)

When we protect something that holds its value, we are maintaining its integrity

- Integrity
    <br/>
    Data is known to be correct and trusted (we can do this through hashing, checksum, sometimes digital signatures)

When we protect something that produces value, we are maintaining its availability

- Availability
    <br/>
    Information is available for use by legitimate users when it is needed (we can do this through building high availability and redundancy into our system)

<b>Real World Example</b>

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
<https://web.mit.edu/Saltzer/www/publications/protection/>

![Protection of Information in computer systems](image/README/Protection%20of%20Information%20in%20computer%20systems.png)

![Security Pyramid](image/README/Security%20Pyramid.PNG)

OWASP WebGoat
<https://owasp.org/www-project-webgoat/>

<hr/>

## Introduction to OWASP Top 10 [2021]

**1. Broken Access Control**
Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other user's accounts, view sensitive files, modify other users' data, change access rights, etc.

**2. Cryptographic Failures**
Failure to sufficiently protect data in transit or rest from exposure to unauthorized individuals. This can include poor usage of encryption or the lack of encryption all together.

**3. Injection**
Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

**4. Insecure Design**
Failing to build security into the application early in the design process through a process of threat modeling, and secure design patterns and principles.

**5. Security Misconfiguration**
Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigurated HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.

**6. Vulnerable and Outdated Components**
Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

**7. Identification and Authentication Failure**
Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, ot to exploit other implementation flaws to assume other users' identities temporarily or permanently.

**8. Software and Data Integrity Failures**
Code or infrastructure that does not properly protect against integrity failures like using plugins from untrusted sources that can lead to a compromise.

**9. Insufficient Logging and Monitoring Failures**
Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.

**10. Server-Side Request Forgery**
SSRF occurs when an application fetches resources without validating the destination URL. This can be taken advantage of by an attacker who is able to enter a destination of their choosing.

### OWASP Help

OWASP offers that are great hints and series and frameworks that can be leveraged during the development process and all throughout the testing, the application testing and development process.

### OWASP Projects

- **Flagship**
The OWASP Flagship destination is given to projects that have demonstrated strategic value to OWASP and application security as a whole
<br/>

- **Lab**
OWASP Labs projects represent projects that have produced a deliverable of value
<br/>

- **Incubator**
OWASP Incubator projects represent the experimental playground where projects are still being fleshed out, ideas are still being proven and development is still underway
<br/>

- **Low Activity**
These projects had no release in at least a year. However, have shown to be valuable tools Code [Low Activity] Health Check February 2016

### How to start with OWASP

OWASP Top 10: the classic guideline
<https://owasp.org/www-project-top-ten/>

OWASP Cheat Sheets to get into stuff without getting annoyed
<https://github.com/OWASP/CheatSheetSeries>

Tools:

- Security Shephard
<https://github.com/OWASP/SecurityShephard>
- WebGoat
<https://owasp.org/www-project-webgoat/>

- OWASP Juice Shop
<https://owasp.org/www-project-juice-shop/>

- OWASP ZAP (Zed Attack Proxy)
<https://www.zaproxy.org/>

- OWTF (Offensive Web Testing Framework)
<https://owasp.org/www-project-owtf/>

- OWASP ASVS
<https://owasp.org/www-project-application-security-verification-standard/>

- Secure Coding Practices Quick Reference Guide
<https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/>

- Java HTML Sanitizer
<https://owasp.org/www-project-java-html-sanitizer/>

- CSRF Guard Project
<https://owasp.org/www-project-csrfguard/>

- ESAPI
<https://owasp.org/www-project-enterprise-security-api/>

- Developers Guide
<https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/>

- Security Knowledge Framework
<https://owasp.org/www-project-security-knowledge-framework/>

- OWASP Testing Guide
<https://owasp.org/www-project-web-security-testing-guide/>
- Code Review Guidelines
<https://owasp.org/www-project-code-reviews-guide/>

- Dependency Check
<https://owasp.org/www-project-dependency-check/>

- Dependency Track
<https://owasp.org/www-project-dependency-track/>

- DefectDojo
<https://owasp.org/www-project-defectdojo/>

### SANS 25

<https://www.sans.org/top25-software-errors/>

![SANS 25](image/README/SANS%20Top%2025.PNG)

<b>Examples in the Top 25</b>
![Example SANS Top 25](image/README/Example%20SANS%20Top%2025.PNG)

![Example SANS Top 25 (2)](image/README/Example%20SANS%20Top%2025%20(2).PNG)

### OWASP vs SANS

![OWASP vs SANS](image/README/OWASP%20vs%20SANS.PNG)

### Threat Actors and Definition

- **Confidentiality**
Concept of preventing the disclosure of information to unauthorized parties
<br/>

- **Integrity**
Refers to protecting data from unauthorized alteration
<br/>

- **Availability**
Access to systems by authorized personnel can be expressed as the system's availability
<br/>

- **Authentication**
Authentication is the process of determining the identity of a user
<br/>

- **Authorization**
Authorization is the process of applying access control rules to a user process, determining whether or not a particular user process can access an object
<br/>

- **Accounting (Audit)**
Accounting is a means of measuring activity
<br/>

- **Non-Repudiation**
Non-Repudiation is the concept of preventing a subject from denying a previous action with an object in a system
<br/>

- **Least Privilege**
Subject should have only the necessary rights and privileges to perform its current task with no additional rights and privileges
<br/>

- **Separation of Duties**
Ensures that for any given task, more than one individual needs to be involved
<br/>

- **Defense in Depth**
Defense in depth is also known by the terms layered security (or defense) and diversity defense
<br/>

- **Fail Safe**
When a system experiences a failure, it should fail to a safe state (Doors open when there is a power failure)
<br/>

- **Fail Secure**
The default state is locked or secured. So a fail secure lock locks the door when power is removed.
<br/>

- **Single point of failure**
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
<b>Exploitation</b> of a <b>vulnerability</b> by a <b>threat</b> results in <b>risk</b>.

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
Attacker substitutes ID of their resource in API call with an ID of a resource belonging to another user. Lack of proper authorization checks allows access. This attack is also known as IDOR (Insecure Direct Object Reference)

- **Example**
An API that allows for an attacker to replace parameters in the URL that allows the attackers to have access to an API that they should not have access to. The API is not checking permissions and lets the call through.

- **Prevention**
  - Implement access checks on every call
  - Do not rely on user supplied IDs, only use IDs in the session object
  - Use random, non-guessable IDs

##### Broken Authentication
-  **Definition**
Poorly implemented API authentication allowing attackers to assume other users' identities.

- **Example**
Unprotected APIs, weak authentication, not rotating or reusing API keys, poor password usage, lack of token validation and weak handling

- **Prevention**
  - Check all authentication methods and use standard authentication, token generation/management, password storage, and MFA
  - Implement a strong password reset API
  - Authenticate the client calls to API
  - Use rate-limitations to avoid brute forcing

##### Excessive Data Exposure
-  **Definition**
API exposing a lot more data than the client legitimately needs, relying on the client to do the filtering. Attacker goes directly to the API and has it all.

- **Example**
Returning full data objects from the database or allowing for direct access to sensitive data.

- **Prevention**
  - Never rely on the client to filter data, and tailor API responses to the needs of the consumer. Ensure that there is a need-to-know for any PII returned
  - Ensure error responses do not expose sensitive information

##### Lack of Resource and Rate Limiting
-  **Definition**
API is not protected against an excessive amount of calls or payload sizes. Attackers use that for DoS and brute force attacks.

- **Example**
Attacker performs a DDoS or otherwise overwhelms the API.

- **Prevention**
  - Include rate limting, payload size limits, check compression ratios, and limit container resources

##### Broken Function Level Authorization
-  **Definition**
API relies on client to use user level or admin level APIs. Attacker figures out the "hidden" admin API methods and invokes them directly.

- **Example**
Administrative functions that are exposed to non-admin users.

- **Prevention**
  - Deny all access by default and build permissions from there based on specific roles
  - Test authorization through tools and manual testing

##### Mass Assignment
-  **Definition**
The API takes data that client provides and stores it without proper filtering for allow-listed properties.

- **Example**
Payload received from the client is blindly transformed into an object and stored.

- **Prevention**
  - Do not automatically bind incoming data without validating it first through an explicit list of parameters and payloads that you are expecting
  - Use a readOnly schema for properties that should never be modified
  - Enforce the defined schemas, types, and patterns that are accepted

##### Security Misconfiguration
-  **Definition**
Poor configuration of the APIs servers allows attackers to exploit them.

- **Example**
Numerous issues like unpatched systems, overexposed files and directories, missing or outdated configuration, exposed systems and unused features, verbose error messaging.

- **Prevention**
  - Use of hardened images and secure default configuration
  - Automation to detect (and repair) discovered misconfiguration
  - Disable unnecessary features, and limit admin access

##### Injection
-  **Definition**
Attacker constructs API calls that include SQL-, NoSQL-, LDAP-, OS- and other commands that the API or backend behind it blindly executes.

- **Example**
SQL, LDAP, OS, XML injection

- **Prevention**
  - Never trust end-user input
  - Have well-defined input data: schemas, types, string patters, etc.
  - Validate, filter, sanitize and quarantine (if needed) data from users

##### Improper Assets Management
-  **Definition**
Attacker finds non-production versions of the API: such as staging, testing, beta or earlier versions - that are not as well protected and uses those to launch the attack.

- **Example**
Backwards compatibility can leave legacy systems exposed. Old and non-production versions can be poorly maintained yet still have access to production data. These also allow for lateral movement in the system.

- **Prevention**
  - Properly inventory your systems and APIs
  - Limit access to anything that should not be public and properly segregate prod and non-prod environments
  - Implement security controls on the network and system such as API firewalls
  - Have a decommission process for old APIs and systems

##### Insufficent Logging and Monitoring
-  **Definition**
Lack of proper logging, monitoring, and alerting let attacks go unnoticed.

- **Example**
Logging and alerts go unnoticed or are not responded to. Logs are not protected against tampering and are not integrated into a centralized logging system like a SIEM.

- **Prevention**
  - Properly log sensitive workflows like failed login attempts, input validation failures, and failures in security policy checks
  - Ensure logs are formatted so that they can be imported in a centralized tool. Logs also need to be protected from tampering and exposure to unauthorized users
  - Integrate logs with monitoring and alerting tools
