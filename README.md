Pyersinia: Network Attack Tool
==============================


![Logo](https://raw.githubusercontent.com/abirtone/STB/master/stb_lib/doc/images/logo.png)


Code | https://github.com/nottinghamprisateam/pyersinia
---- | ----------------------------------------------
Final version | 1.0.3
Issues | https://github.com/nottinghamprisateam/pyersinia/issues/
Python version | Python 2 and 3

¿Qué es Pyersinia? // What's pyersinia?
----------------

Pyersinia es un framework similar a la herramienta Yersinia, pero implementada en Python utilizando la librería Scapy. El objetivo principal es la realización de ataques de red como ARP spoofing, DHCP DoS, STP DoS entre otros. La comunidad puede añadir nuevos ataques a la herramienta de una manera sencilla, mediante plugins. Esto es gracias a que Pyersinia utiliza el framework STB (Security Tools Builder).
	
Pyersinia is a similar tool to Yersinia, but Pyersinia is implemented in Python using Scapy. The main objective is the realization of network attacks such as spoofing ARP, DHCP DoS , STP DoS among others. The community can add new attacks on the tool in a simple way, using plugins. This is because Pyersinia uses the STB (Security Tools Builder) framework.

Novedades // What's new?
-----------

Añadir nuevos ataques a la herramienta se hace una tarea bastante sencilla debido a que la 
herramienta esta implementada sobre el framework STB (Security Tool Builder). Mediante 
plugins se podrán añadir los nuevos ataques de red. 

Adding new attacks on the tool is a simple task because we use the framework STB (Security Tool Builder). 
The new attacks are added by plugins. 

Installation
------------

Install pyersinia is so easy:

```
$ python -m pip install pyersinia
```

Quick start
-----------

You can display inline help writing:

```bash

python pyersinia.py -h
```

Advanced options
----------------

There are the advanced options:

**-v**, **-vv**, **-vvv**: Enable verbose mode.

References
----------

- OMSTD (Open Methodology for Security Tool Developers): http://omstd.readthedocs.org
- STB (Security Tool Builder): https://github.com/abirtone/STB
- Yersinia: https://github.com/tomac/yersinia
