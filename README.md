# opentsdb_key_cmd_injection
An exploit for OpenTSDB <= 2.4.1 cmd injection (CVE-2023-36812/CVE-2023-25826) written in Fortran
# About
This is an exploit for a command injection vulnerability in OpenTSDB verions 2.4.1 and prior (CVE-2023-36812/CVE-2023-25826). The exploit is written in modern Fortran and leverages the official Fortran [http-client library](https://github.com/fortran-lang/http-client) that was created earlier this year.

# Vulnerability details
OpenTSDB is an open-source time series database written in Java. In 2020, a command injection vulnerability was discovered in versions 2.4.0 and prior that could be exploited in order to gain remote code execution on the host with root privileges. Since OpenTSDB does not support authentication, this vulnerability, tracked as CVE-2020-35476, could be exploited by anyone with access to the OpenTSDB web interface. A patch was released as part of version 2.4.1

This year it was discovered that the patch for CVE-2020-35476 was incomplete, and command injection is still possible in OpenTSDB 2.4.1 via several vectors. The OpenTSDB maintainers have released a [security advisory](https://github.com/OpenTSDB/opentsdb/security/advisories/GHSA-76f7-9v52-v2fw) for this issue, which is tracked as CVE-2023-36812 and credited to Gal Goldstein and Daniel Abeles of Oxeye. It is worth nothing that CVE-2023-25826 actually seems to describe the same vulnerability, and both CVEs link to the exact same patch. Said patch will be introduced in 2.4.2, which is not an official release yet. At the time of writing, the most recent OpenTSDB [release](https://github.com/OpenTSDB/opentsdb/releases) on GitHub remains 2.4.1, and the [OpenTSDB website](http://opentsdb.net/) also mentions 2.4.1 as the current version. It's therefore likely that most OpenTSDB instances in production are still running a vulnerable version. That being said, the OpenTSDB [FAQ]http://opentsdb.net/faq.html emphasizes that this project "was written for internal use only", and "hasn't been through any security review and does not included authentication."

# Why Fortran?
The short version is that I saw this convo:

The idea of writing an exploit in [the programming language used to put people on the moon](https://www.linux.com/news/how-they-built-it-software-apollo-11/) intruiged me so much that I had to explore it myself. This exploit is the result of that experiment. To the question whether it was successful, I can respond only with these wise, yet cursed words that bind all devs in blood: It works on my machine. ¯\\_(ツ)_/¯

In any case, my key takeaways from this project are:
- Fortran is actually pretty cool, and suprisingly easy to learn.
- The modern Fortran ecosystem, including the [fpm](https://github.com/fortran-lang/fpm) package manager, shows great promise.
- Fortran is a strongly typed language, and I found that to be a good thing, because I encountered few nasty run-time errors.
- Fortran projects with dependencies are large because fpm includes the dependency source code directly into your project. The benefit is that it avoids system pollution.
- Library support is relatively limited and chaotic compared to modern languages. Unfortunately this does not just affect the http-client library.
- Unsurprisingly, good documentation and troubleshooting tips are harder to come by than for most modern programming languages, though there are still quite a few useful posts on StackOverflow and long-forgotten forums from the early 2000s.
- AI tools like ChatGPT and GithHub Copilot make for even less reliable coding buddies than is the case for modern languages.

All in all, it is not easy to imagine this language really gaining significance within offensive security, if only because there are so many solid, modern alternatives out there for any imaginable use case (Python, Go, Rust, Ruby, C# to name just a few). But if you like experimenting with different programming languages and don't mind encapsulating your strings in `trim()` calls all the time (PLEASE TAKE NOTE OF THIS IT WILL SAVE YOU SO MUCH SUFFERING), Fortran is absolutely worth checking out. I'm unironically rooting for this language now and I might revisit it if they continue to add support to the http-client library, especially if they add an http-server library at some point.

TL;DR: Fortran http-client lib goes brr.

# Usage
- Start a listener on your system, eg:
```
nc -nlvp 1337
```
- In a separate window, nagivate to the `opentsdb_key_cmd_injection` directory
```
# cd /path/to/opentsdb_key_cmd_injection/
```
- Run the project via `fpm` (make sure to install it first. See the installation instructions in the next section)
```
# /path/to/fpm run -- -t <target_url> -l <lhost> -p <lport> [-v]
```
Options:
- `-t` - TARGET URL: the base URL to OpenTSDB (required)
- `-l` - LHOST: the IP of the system where you are running a listener (required)
- `-p` - LPORT: the listener port (required)
- `-v` - VERBOSE: enable verbose printing (optional)

# Installation
- Install `gfortran`. On debian-based systems this can be done via:
```
apt install gfortran
```
- Install fpm. The easiest way to do this is to download a binary for the latest stable release from the fpm [releases](https://github.com/fortran-lang/fpm/releases/latest) on GitHub and then make it executable:
```
chmod +x /<path>/to/fpm
```
Make sure you have `git` installed on your system before installing `fpm`.

# A brief history of Fortran
Fortran is mostly known as an archaic language that played an important role in the history of modern computing, but can no longer be considered relevant today. It was first released in 1957, predating both the ARPANET and Unix by more than a decade. Based on [this time-series data video](https://www.youtube.com/watch?v=qQXXI5QFUfw) it was the dominant programming language throughout the 1960s and 1970s, and remained among the 10 most popular languages until the late 1990s. But by the time Windows 98 was released, it had clearly fallen out of fashion, in favor of more modern languagues like C, C++, Java and JavaScript, all of which are still widely used today.

Apart from the brave souls who manage legacy systems, I doubt that many people in IT (let alone outside of our bubble), have come across Fortran in the last two decades, or are even aware that it's still around. Despite that, Fortran remains under active development. As stated on the [offical Fortran website](https://fortran-lang.org/), the language was last revised in 2018, and we will hopefully see another revision this year (2023). In fact, it seems the Fortran community has been very active in the last few years, pushing out several major projects to help modernize the ecosystem, including:
- [stdlib](https://github.com/fortran-lang/): the first-ever Fortran standard library (first release: 2021)
- [fpm](https://github.com/fortran-lang/fpm): a modern package manager and build system called fpm (first alpha release: 2020)
- [http-client](https://github.com/fortran-lang/http-client): the previously referenced HTTP client library (first release: 2023).

Given this, it appears the maintainers are aiming for somewhat of a Fortran comeback, or at the very least to give the language a fighting chance to survive for a few more decades. While even the most fanatic Fortran stan probably doesn't expect to see the language crack the top 10 of most popular programming languages ever again, the ongoing modernization of the language and its ecosystem has likely made Fortran more relevant than it has been in the last decade or two.
