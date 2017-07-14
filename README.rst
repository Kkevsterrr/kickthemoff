KickThemOff
============

`KickThemOff <https://github.com/Kkevsterrr/kickthemoff>`_ - **Kick Devices Off Your Network**

An offensive toolset to kick devices and rewrite arp rules.

Compatible with Python 2.6 & 2.7.

Authors: `Kkevsterrr`_ 
Based on prototype by Nikolaos Kamarinakis <mailto:nikolaskam@gmail.com>`_  & `David Schütz <mailto:xdavid@protonmail.com>`_.

.. image:: https://nikolaskama.me/content/images/2017/01/kickthemout.png

Installation
-------------

You can download KickThemOff by cloning the `Git Repo <https://github.com/Kkevsterrr/kickthemoff>`_ and simply installing its requirements::

    $ git clone https://github.com/Kkevsterrr/kickthemoff.git
    
    $ cd kickthemoff/
    
    $ sudo pip install -r requirements.txt

Mac OS X Installation
----------------------

If you would like to install KickThemOff on a Mac, please run the following::

    $ sudo pip install pcapy
    
    $ brew install libdnet scapy

Keep in mind that you might be asked to run some commands after executing the previous step. Moving on::

    $ git clone https://github.com/Kkevsterrr/kickthemoff.git

**NOTE**: You need to have `Homebrew <http://brew.sh/>`_ installed before running the Mac OS installation.

Demo
-----

Here's a short demo:

.. image:: https://nikolaskama.me/content/images/2017/01/kickthemout_asciinema.png
   :target: https://asciinema.org/a/98200?autoplay=1&loop=1

(For more demos click `here <https://asciinema.org/~k4m4>`_.)

Disclaimer
-----------

KickThemOff is provided as is under the MIT Licence (as stated below). 
It is built for educational purposes only. If you choose to use it otherwise, the developers will not be held responsible. 
In brief, do not use it with evil intent.

License
--------
Based on original project KickThemOut.
Original project copyright (c) 2017 by `Nikolaos Kamarinakis <mailto:nikolaskam@gmail.com>`_ & `David Schütz <mailto:xdavid@protonmail.com>`_. Some rights reserved.
