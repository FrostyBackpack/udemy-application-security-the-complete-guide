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


## Security
Security is anything you do to protect an <u>asset</u> that is <u>vulnerable</u> to some <u>attack</u>, <u>failure</u>, or <u>error</u> [threats]

- Asset
  An **asset** is anything you deem to have **value**
  <br/>
  An asset may be valuable because:
  - It <u>holds</u> its value (E.g. gold/diamonds)
  - It <u>produces</u> value (E.g. Technology space, a server in a data center - running applications produce value to organization)
  - It <u>provides access</u> to value (E.g. a PIN number to a bank account to get money - something that needs to be protected)

- Vulnerability
  A vulnerability is any weakness in an asset that makes it susceptible to attack of failure

- Attack
  An attack is any <u>intentional</u> action that can reduce the value of an asset
  <br/>
  E.g. An attacker might perform a DDoS attack on that web server to reduce value for organisation intentionally

- Failures + Errors
  Failures and errors are <u>unintentional</u> actions that can reduce the value of an asset
  <br/>
  E.g. There might be an unplanned outage because of a power outage or maybe a new push for a patch that gets pushed at web server that does not work that creates an outage for that web server, making it unavailable for organisation so it reduce value unintentionally

Attacks, Failures and Errors are actions that we collectively refer to as <u>threats</u>

### Security Goals ("Anything"):
Security, an more specifically Cybersecurity, can be understood as a set of goals

These goals are specifically defined by how we measure an asset's value

How does value define our security goals?
- The goal of security is to protect an asset's <u>value</u> from threats

1. Determine what assets we want to protect
2. Learn how the asset works and interacts with other things
3. Determine how our asset's value is reduced directly and indirectly
4. Take steps to mitigate the threats

We must consider the unique nature of it assets and capabilities when considering security goals.

##### CIA prinicples:
<br/>
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

Real World Example:
- About a rocket:
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

- How we secure it:
  Based on the list of vulnerabilties and threats, we can have different ways that we could mitigate it. 
  <br/>
  For instance, we could make the hole thicker or with using more duarble material. However, that could also alter things in the sense that we might make the rocket heavier and therefore, we would need more fuel to get it up or we could have less cargo space.
  <br/>
  Hence, the concept is making sure that the mitigations and the security that we put around our assets are in line with what the actual assets value is and make sure that we're not compromising the asset further by creating more complicated mitigations or remediation strategies.

We have well defined goals and security mechanisms, but some mechanisms are better because they fit <u>security principles</u>

Security principles aid in selecting or designing the correct mechanisms to implement our goals

[Doc] Protection of information in computer systems:
https://web.mit.edu/Saltzer/www/publications/protection/

![Protection of Information in computer systems](image/README/Protection%20of%20Information%20in%20computer%20systems.png)


![Security Pyramid](image/README/Security%20Pyramid.PNG)

OWASP WebGoat:
<br/>
https://owasp.org/www-project-webgoat/
