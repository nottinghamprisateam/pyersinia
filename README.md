Pyersinia: Network Attack Tool
==============================


Code | https://github.com/nottinghamprisateam/pyersinia
---- | ----------------------------------------------
Final version | 1.0.5
Issues | https://github.com/nottinghamprisateam/pyersinia/issues/
Python version | Python 2, Python 3


What's pyersinia?
-----------------

Pyersinia is a similar tool to Yersinia, but Pyersinia is implemented in Python using Scapy. The main objective is the realization of network attacks such as spoofing ARP, DHCP DoS , STP DoS among others. The community can add new attacks on the tool in a simple way, using plugins. This is because Pyersinia uses the STB (Security Tools Builder) framework.


What's new?
-----------

Adding new attacks on the tool is a simple task because we use the framework STB (Security Tool Builder). 
The new attacks are added by plugins. 


How to contribute to this project
---------------------------------
(Link sphinx)


Installation
------------

Install pyersinia is so easy:

```
$ python -m pip install pyersinia
```

Or install from Pypi:

```
$ pip install pyersinia
```


Quick start
-----------

You can display inline help writing:

```bash

python pyersinia.py -h
```

References
----------

- OMSTD (Open Methodology for Security Tool Developers): http://omstd.readthedocs.org
- STB (Security Tool Builder): https://github.com/abirtone/STB
- Yersinia: https://github.com/tomac/yersinia
