# PDF Sentinel 
**Protect Your Files with Ease**
PDF Sentinel is a blazing-fast, intuitive, and user-friendly security tool that empowers anyone to scan their files for hidden viruses and malware quickly.

# Problem
PDFs have been a popular vector for malware attacks. This has been been on the [rise](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/rise-in-deceptive-pdf-the-gateway-to-malicious-payloads/) and its a really devasting and widespread attack as the virus injected by the PDFs can steal critical credentials to a user's bank account and more. 

Some notable examples of malware that have been spread through PDFs include:

1. **Emotet**: A highly sophisticated trojan that has been spread through PDFs, causing widespread damage and disruption.
2. **[TrickBot](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-076a)**: A banking trojan that has been spread through PDFs, targeting users' financial information.
3. **Ryuk**: A ransomware variant that has been spread through PDFs, causing significant disruption and financial losses.

However there has not been an easy way that is accessible to many for them to scan their pdfs for malware. Therefore there is need for more effective and user-friendly solutions to detect and prevent PDF-based malware attacks.

## Problems with Current Landscape

Traditional PDF malware detection solutions typically employ signature-based detection, sandboxing, or static analysis. However, sophisticated attackers have developed evasion techniques such as:

- Code obfuscation
- Anti-debugging measures
- File format manipulation


These tactics allow malicious PDFs to bypass conventional security controls, leaving many PDF-based malware attacks undetected and putting users and organizations at risk.

Moreover, existing solutions often require technical expertise, making them challenging for end-users without a background in technology to understand and utilize effectively. Many of them are command line tool, not accessible to an average user. This creates a significant gap in protection for the average user. 

For instance, many users frequently receive files through messaging platforms like Telegram. However, determining whether these files are malicious can be difficult without proper tools and knowledge.

There is a clear need for a user-friendly, accessible solution that can help individuals easily scan and verify the safety of PDF files they receive or download, regardless of their technical proficiency.

## Existing Tools
### Free Tools
These are the current existing free tools out there: 
- [PDF Tools](http://blog.didierstevens.com/programs/pdf-tools/) suite by Didier Stevens
- [PDF Stream Dumper](http://sandsprite.com/blogs/index.php?uid=7&pid=57)
- [Jsunpack-n](https://code.google.com/p/jsunpack-n/)
- [Peepdf](http://eternal-todo.com/tools/peepdf)
- [Origami](http://esec-lab.sogeti.com/dotclear/index.php?pages/Origami)
- [MalObjClass](https://github.com/9b/malpdfobj)

Take a look at them ... There's one thing in common, they look super outdated, boring and insanely technical. 
### Anti Viruses

So you might be thinking why not just buy an antivirus or trust my anti virus to catch the malware from the PDF? Here's why
1. **Kernel access**: Many antiviruses require kernel access to function effectively. This means they need to run at the kernel level, which can introduce security risks if the antivirus software itself is vulnerable to exploits. This is the case with crowdstrike and why they brought down so many computers. 
2. **Signature-based detection**: Traditional antiviruses rely on signature-based detection, which means they identify malware by matching files against a database of known malware signatures. However, this approach has limitations:
	1. - **New malware variants**: New malware variants may not be recognized by the antivirus software, allowing them to evade detection.
	2. **Zero-day attacks**: Zero-day attacks exploit previously unknown vulnerabilities, making it difficult for antiviruses to detect them. 
	3. **Polymorphic malware**: Polymorphic malware can change its form and evade detection by traditional antiviruses.

TLDR, check this Reddit post [out](https://www.reddit.com/r/linux4noobs/comments/16h7519/why_is_antivirus_so_hated_or_disregarded/).


# Solution
PDF Sentinel is an open-source tool that solves a critical problem not addressed by current solutions: **detecting and preventing PDF-based malware that uses evasion techniques to evade traditional security controls**.


## Design Principles

An important design criterium for this program is simplicity. Parsing a PDF document completely requires a very complex program, and hence it is bound to contain many (security) bugs. To avoid the risk of getting exploited, I decided to keep this program very simple.

Mobile friendly, modular backend that can be adapted to different front ends. Most of us open our pdfs on our phone, so the user experience and ease of use is really important. 

The solution should be self contained in a sandboxed environment, so that if there were any exploit the program would not be affected and would not affect other pdfs that are used. That said, it means that the program should be made in a way that is really easy to run by anyone. 

Usage of machine learning methods to 


## Analysing and Identification of Malware

### Other Ideas
* Telegram bot
	* Telegram bot that allows you to forward your file over and scan it for viruses. Pay with Ton tokens if the file exceeds x size. Maybe the ux could even be simplified either in virus scanning, privacy, minimising trust etc.

* Using LLM apis as a freemium model
	* Machine learning models as freemium features
* Dashboard of threats discovered

# TODO
* [ ] Research about the current state of solution
	* [ ] Look at their implementation
	* [ ] See what might be missing
* [ ] Write a simple writeup of the solution
* [ ] Do a linkedin post on this to get user thoughts and feedback. Do a web app first


# References

Malicous PDFs
* [Malicous PDF](https://www.sentinelone.com/blog/malicious-pdfs-revealing-techniques-behind-attacks/)
