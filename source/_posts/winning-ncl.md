---
title: 'Winning NCL (Fall 2025)'
date: 2025-11-24 00:00:00
tags: 
- ncl
---

# Winning NCL (Fall 2025)
I have played NCL so many times I've lost count. I started back in like 2021 or so and have played almost every semester until now. My team (BYU Cyberia) got first place, which means I never have to play NCL again (honestly probably should have done that a while ago). In this blog post, I'm going to outline the meta for winning NCL (and probably complain about it too).

NCL stands for [National Cyber League](https://nationalcyberleague.org/), and it's a CTF put on by Cyber Skyline every semester for US-based high school and university students. It typically gets around 6,000 individual participants a semester, and between 1-2k teams. NCL has an admission fee of $45 (which is wack), and is split into 4 parts (you can do all of them):

* **Gym** → you get like 2 months of access to a handful of previous (mostly easy) challenges so you have time to prep
* **Practice Game** → meant to run just like the Individual Game, I think it also uses old challenges? More for teaching newbies how a CTF operates
* **Individual Game** → everyone competes individually, runs a couple weeks after the practice game
* **Team Game** → you can compete in teams of up to 7 players, runs a couple weeks after the individual game

Individual/Team Games are 56 hours, going from 11am Friday MST to 7pm Sunday MST. You've got categories including OSINT, cryptography, password cracking, log analysis, network traffic analysis, forensics, scanning & reconnaissance, enumeration and exploitation, and web exploitation. While there are a few "offensive" categories, I would consider it mostly a blue team CTF as that's what it focuses most on.

## Team
Just as a quick note, we usually have 7 people on our team, but we ended up having 6 people on our team this last NCL. To win, I recommend a minimum of 5 fully committed players, but the more the merrier. We ensure that anyone doing NCL with us has the entire weekend booked months in advance. Outside of classes or like a 1-2 hour commitment that weekend, everyone is hunkered down in the basement of our lab together from the moment it starts until it's over. I always let them know from the start that that's how it goes - if someone is like "oh I'll pop in from like 3-5pm" or something, it's a no-go. Also since BYU is a religious school, no one is expected to compete on Sundays if they don't want to. Some of us will get together, others won't, each person gets to choose. The goal is to be done by then anyways 😂.

We also try to recruit people that have more experience in different areas. Getting 1 or 2 people who have done a lot of rev/pwn, getting a web guy/girl, an OSINT guy/girl, a <s>keyboard monkey</s> crypto guy/girl, etc. is good to help balance out the team properly (if possible).

## Accuracy
The biggest difference between NCL and other CTFs is the emphasis on accuracy; also most of the NCL meta focuses on preserving accuracy. In all other CTFs known to mankind, the team with the most points win, and if two teams are tied with points, then whoever got there **first** (took the shortest amount of time) wins. In NCL, points are first, but **accuracy is second**. This means that Team 1 can full solve NCL in 8 hours with 99% accuracy, but if Team 2 comes along and also full solves in 55 hours with 100% accuracy, Team 2 gets first place. Assuming two teams tie with points *and* accuracy, only then does "time of last solve" become the tiebreaker.

This is a complete game changer, as you now need to prioritize having perfect accuracy over solving challenges fast. Okay you may be wondering though, how often do ties like this occur (especially at the top of the leaderboard)? The answer is almost every single semester - my team has placed top 5 like 5 times, and have seen firsthand how important accuracy is. NCL is geared towards beginners, so while they occasionally have a technically difficult challenge (more often just guessy challenges that are "hard"), any top team can be expected to full solve the CTF (especially if they have professional CTF players). We have always gone into NCL with this assumption - both us and multiple other teams will likely full solve, so **we need perfect accuracy even if it means delaying submitting challenges**.

Our method to ensure perfect accuracy is:
- Use a spreadsheet to track all your answers
- Have multiple people independently solve each challenge
- Duke it out until everyone on the team is fully satisfied with the answer
- Only have one person submit the answer while everyone watches them

### Spreadsheet
This was an idea that someone mentioned in the NCL discord a while ago that I picked up, but it's been an absolute game changer. During the first hour of every NCL, our team will do nothing except fill out the spreadsheet. You can see a blank view-only copy here → https://docs.google.com/spreadsheets/d/1hk19lb7aAFO3ZNJDTi43PVRmEaBPEuCT1k9HV_V_PUA/edit?usp=sharing (you are free to clone this and use it yourself for NCL).

<img src="/static/winning-ncl/spreadsheet.png" width="900px">

Every single question gets its own row. Cells are merged so each category and problem has each individual question in it. The point values for each question is filled in, along with the names and difficulty. Then, there are two spots for answers (and a spot for who put the answer there to the left of it). When the first person solves the challenge, they put the answer in their slot and the spreadsheet will automatically black it out. This ensures that the answer is preserved, but when a teammate comes along to solve the challenge on their own, **they don't see Person 1's answer and have that bias their approach**. We really want people to independently solve each challenge! Once both people put an answer down, they can see whether the answers match or not. If they don't, it's time for some healthy debate and a third person to look at it. Once the answer is submitted, you can check the box. There's also a couple cells at the bottom to keep track of how many points we're missing across the board.

Now, for some challenges or categories, fully independently solving it doesn't really make sense or is unnecessary. This includes password cracking or challenges where an answer in the flag format is obtained. However, a teammate can still verify the answer in some way. For password cracking, we'll copy all the hashes and all the supposed passwords from the spreadsheet into new files and recrack it with just that wordlist. For challenges where you obtained a flag in the flag format, one teammate can send the commands/scripts they used, and the second teammate can run it to get the flag themselves and verify it was copied into the spreadsheet correctly. It may seem a little over the top, but being super OCD about it ensures no stupid mistakes cost you the competition.

### Submitting Answers
Okay, so you've filled out at least part of the spreadsheet with at least two people independently solving each challenge and you want to start putting points on the scoreboard - what's next? Our team usually spends **all day Friday** just filling out the spreadsheet and we don't submit a single answer until at least Saturday morning/afternoon. Guys to be 100% honest, the state of the scoreboard in the first 24/36 hours **means nothing**. You can be 1st Friday night and end up in 76th place by Sunday evening.

<img src="/static/winning-ncl/timeline.png" width="650px">

Anyways, most of the easier problems are double or triple solved after the first 24 hours and we want to get those out of the way so we can just focus on what remains. We all get together in the same room and sit around a table. I share my screen on a mounted TV and we choose a problem that has been double/triple solved. We'll give those who solved it "the talking stick" and they explain the challenge and how they solved it. Bonus points if the teammates solved it different ways. A majority of the time, I'll have them send me the commands/scripts and I'll solve it myself there on the spot with everyone watching.

It's this point where anyone on the team can ask clarifying questions or state they're not comfortable with submitting the answer right now, pending their personal confirmation of the answer or waiting on the response from a support ticket. Assuming everyone is okay with it though, we verify that the answer in the spreadsheet is what we're expecting. I then highlight *everything in the answer cell*, copy it, go to the NCL browser window, and paste it in the answer box. I CTRL+A to highlight everything in the answer box to ensure I correctly copied *everything* over, and didn't accidentally copy something like a space. I look around for confirmations or a thumbs up from people, and click the Submit button (I don't press ENTER because I'm too worried about accidentally pressing the `\` button or something).

This probably sounds really stressful and time-intensive, and you would be right (especially if you're the one actually submitting it like me 😭). Thus is the game of NCL. We often take breaks after a category to let the stress die down a bit before we move on. This process usually takes around 2 or 3 hours for the first time where we submit a lot of answers. Then, we identify challenges we want to be more positive about or haven't finished/been able to work on, and we continue the work. 

We usually sit down and repeat this whole process about 4 or 5 hours later once we filled in most other things. At that point, it's Saturday mid-evening and we typically only have a few (hard or guessy) challenges left to solve that we all focus on.

### Accuracy Conclusion
You may think we're crazy for going this hard-core (and you're probably right), but if you can't stand getting a place other than 1st, we have found that This Is The Way. Note that little dot on the far top right is us - we were the only team that got 100% and 100% completion for Fall 2025 (Experienced Bracket), and we finished Saturday evening (ignoring the broken web challenge).

<img src="/static/winning-ncl/scoreboard.png" width="700px">

## Support Tickets
A majority of the questions are looking for answers that are not in a flag format (I have a rant about that at the bottom of this blog post). That means most challenges you can't be >95% certain your answer is correct. Factor in vague questions or questions that haven't specified an answer format, along with the importance of accuracy, and ambiguity is rampant. One of the best ways to clear up that ambiguity is to file a support ticket with the Cyber Skyline team (another added benefit to not submitting answers until Saturday is *other* teams will have already encountered some bugs/broken challenges and gotten them fixed).

That being said, are the NCL moderators actually helpful in support tickets? Honestly it's a coin toss. Sometimes they will *actually read* your message and look into something and respond with something helpful like "either format works" or "oh yeah, that question is ambiguous, let me clarify it" (looking at you Kiwi 🥰)! And other times, they'll just say "Sorry we can't give hints" or "The challenge works as intended" or "We can't answer that" or "We can't give retroactive credit" (when we didn't even ask for retroactive credit, just reporting a broken challenge 💀). Then they get upset that people are trying to "social engineer" them in the tickets...... who'd've thunk 🤷‍♂️ <s>Maybe if you didn't ask vague questions and grade accuracy you wouldn't have as many tickets</s>

I will also say it's **extremely** frustrating to talk to a team that beat you in previous semesters and learn that they filed a ticket for the exact same issue/question and *actually got a helpful response or even retroactive credit*, while you got stonewalled. Yeah, I have frustrations with how their support works, but regardless, they can still be helpful sometimes. Also, always be kind and respectful and give well-described, thought-out responses to them. Tickets are already enough of a hit-or-miss, being rude to them won't help you at all.

## Category-Specific Notes
* **OSINT, Log Analysis, Forensics, and NTA** → these categories are typically the most vague. We will often require triple solving each challenge and will file tickets to clarify formats or what exactly they're looking for. Go slow, have each person solve the challenges using different commands/tools, and sometimes even *try* to look for another "possibly correct" answer.
* **Scanning & Recon** → yeah I don't really have anything to say here
* **Enumeration and Exploitation** → this category has historically been just basic reverse engineering, but in the last 2 or 3 years they've started adding some more complicated rev problems and even some real pwn problems! This last competition had an IBM mainframe hacking series that was difficult and lots of fun!
* **Web Exploitation** → NCL *only* does blind web, *ever*. I've never seen them give source code (except for that one time they gave us fake source code thinking that it was "close enough"). It's almost always server-side stuff with a focus on enumerating attack surfaces rather than novel attack techniques. They tried a client-side one this time and it was broken for most people. I've done everything from SQL injection to NoSQL injection to race conditions.
* **Cryptography** → NCL never has real crypto. I don't do math (outside of basic calculator stuff), and I've always been able to solve their crypto problems. It's mostly ciphers, with some steg and PGP/guessy AES stuff. I even taught our team 2x 1-hour lectures on the theory of ciphers (even though it has no modern-day use) to try to get ahead on it. My best recommendation? Find yourself a keyboard monkey who will throw everything in the book (including the book) at the wall to see what sticks. There was one cipher challenge that we *could not solve* one year until some guy downloaded a toy cipher app on his phone and it magically worked... thanks Cameron 😁 We had another guy who was working on a cipher challenge and tried every single possible setting for every single option in CyberChef *twice* before figuring out what the right solution was.
* **Password Cracking** → see below

## Password Cracking
Password cracking has historically been our biggest enemy - so many times we'd have everything (or almost everything) else done except for 1 or 2 hard password cracking challenges. After years of research, writing our own scripts, and trial+error, we finally feel like we figured it out. Some years, it was the words in our wordlist that we were missing; other years, it was specific rule variations that we didn't account for. I railed on for years about how the password cracking wasn't feasible..... until we finally got 100% completion last semester, and did it again this semester. So no, <u>you don't need a cluster of 8x 4090s running full time to crack all the passwords</u>. While a few GPUs is generally helpful (and if you are only using CPUs you might still be cooked), it's mostly about optimizing hashcat and cleaning your wordlists.

There's a *lot* that I could say about this, and I will say that I've learned *so much* about optimizing hashcat, so **I decided to open source our base password cracking repo** here → https://github.com/Legoclones/NCL-cracking. 

Note this is not a "drag and drop" solution where you provide a base wordlist and it just gets you everything. It's meant to provide all the right building blocks that you can put together to best meet the description provided for that semester. I have comments on commands to clean wordlists, run you through some optimizations, etc. Have fun.

## Opinion Zone
<img src="/static/winning-ncl/opinion.png" width="500px">

Thank you all for coming to my TED Talk. I'm reserving this section for my main complaints about NCL (not all of them, just the main ones). They fall into **two categories**:

- Accuracy shouldn't be the tie-breaker
- CTFs are meant to have real flags

### Accuracy = Bad
All I'm saying is there's a reason **no other CTFs make accuracy the first tie-breaker**. While it may provide some incentive for middle-of-the-road players to actually think about *what* they submit *before* they submit, it completely changes the meta for winning (as I've described above). It increases the number of "social engineering" or clarification tickets, increases the stress for participants, and I believe the same goal can be achieved by capping the number of possible submissions per challenge (which you already do anyway!) It makes people less worried about stupid mistakes and rewards time to first solve, which I think is more important than accuracy. 

I honestly think many top teams could full clear the CTF in the first 12-24 hours if accuracy was removed. If you're NCL and you think that's a bad idea, **you're wrong**. That just means your CTF is too easy (so add more hard and not guessy challenges), or you just say "I don't care if pros finish early, I only care about providing good challenges for beginners".

### CTFs Need Flags
The whole point of a Capture the Flag competition is that someone can't get points unless they *capture a flag*. The flag needs to be hidden somewhere, whether it's in an executable, memory dump, webserver, or encrypted text. **CTFs are not a form of short answer questions**. 

Asking "How many unique IPs sent a GET request to `/yourmom`?" and having them submit "10" **is not a CTF problem**. It's a short answer problem, and CTFs aren't tests.

Saying "the only way to get the flag is by hacking this website" and then requiring them to hack it **is a CTF problem**. They can't get the points for the challenge unless they actually *solve the challenge* because they don't see the flag unless they *hack the website*.

It's a simple principle, but *so many people* mess it up. This one simple principle is what separates a CTF from an exam. **If you have to specify a flag format, you're doing it wrong**. **If their answer isn't in a flag format, you're doing it wrong**. <s>We're not even going to touch the absolutely wack flag format that NCL has chosen</s> If the type of problem you want to have literally cannot in any way, shape, or form adhere to this principle..... then it doesn't belong in a CTF. Go find your own acronym for that type of competition, leave my precious CTFs alone.

I haven't *super* thought about it, but I can see how "offensive" CTF categories lend themselves to this principle more, and "defensive" categories are more difficult. But I don't care, I think you guys just need to be more creative.

Maybe, instead of "How many unique IPs sent a GET request to `/yourmom`?", you set up a TCP service where every time they connect, you give them a different log file. They have 5 seconds to parse the log file and return whatever metric you're looking for. They have to do that 20 times in a row, and they will be given the flag if they do it successfully. 

BuT jUsTiN tHaT tUrNs It iNtO a ProGrAmMiNg ChAlLeNgE!!! 

Isn't it one already? The whole purpose of the challenge is to ensure that they can properly parse log files to find that kind of information, which requires commands or scripting. I mean, I guess they could literally count it, but I don't think that's what you, as the challenge author, are looking for.

Why does it make a difference? Exams are boring, CTFs are fun. Turning it into a randomly-generated-log-file problem that they have to write code that automatically parses and submits the solution is *fun*, and seeing it work on a server that gives you a flag in the right flag format *is addicting*. Doing it once on a static file is boring and feels like an exam.

Don't agree with me? 1) **mad cuz bad**, and 2) you probably aren't a real CTF player.