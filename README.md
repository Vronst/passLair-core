# password-manager (core)

## Content
- [About](#about)
- [Installation](#instalation)
- [Features](#features)
- [AI Usage](#ai_usage)

## About
Since I started working in IT, I understood the importance of strong password. I also understand how hard it is to remember siad password.
So, I decided I will do a simple app, that will do it for me, and learn some rust on the way (look passlair-crypto).
But after inital draft of simple json storage, I could not accept safety drawbacks from this solution.
I decided to make it as perfect, as I could in a little time I have. So from simple json file,
database and models were created, then it whent further and I researched encryption and
decryption security, keys, nonce/salt... And it went on, instead of simple project I ended up in this situation.
The project is much more safe, and complicated than what I had in mind.
I had to stop in middle and make some helping graphs for plans and... Well I had a lot of fun.

I cannot say that it is perfect. This layer (passlair-core) uses python,
which has garbage collector and no easy memory (RAM) clear. So the passwords may linger there.
Becasue of this lower layer (passlair-crypto) doesn't implement it either.
I think it is not important though, because the password is coppied to clipboard anyway.

## Instalation
To install it (it is library, not finished product!) just simply use pip or better [uv](https://docs.astral.sh/uv/)
```bash
uv add git+https://github.com/Vronst/passLair-core
```
or
```bash
pip add git+https://github.com/Vronst/passLair-core
```
or other similar tools.

## Features
This project works as follow:
*User is created -> from main password DEK is created -> backup DEK is created and displayed once (no strogin) -> password is saved, encrypted with DEK and stored*

Everything can be stored in either sqlite or mariadb, or both (first sql, and then sync to mariadb).

## AI usage
AI was used for creation of majority of tests, small refactors, logger. All the rest is what I have writen myself.
