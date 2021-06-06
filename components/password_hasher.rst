.. index::
   single: PasswordHasher
   single: Components; PasswordHasher

The PasswordHasher Component
============================

    The PasswordHasher component provides secure password hashing utilities.

Introduction
------------

Hashing passwords is the process of applying a `cryptographic hash function`_ to
transform the original plain text password into a different non-guessable value
which is infeasible to invert.

Installation
------------

.. code-block:: terminal

    $ composer require symfony/password-hasher

.. include:: /components/require_autoload.rst.inc

Usage
-----

.. seealso::

    This article explains how to use the PasswordHasher features as an
    independent component in any PHP application. Read the :doc: `/password_hasher`
    article to learn about how to use it in Symfony applications.

Configuring Password Hashers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PasswordHasher component ships with the ``PasswordHasherFactory`` class which is
used to configure different password hashers as follows::

    use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactory;

    // Configure password hashers via the factory.
    $factory = new PasswordHasherFactory([
        'auto' => ['algorithm' => 'auto'],
        'bcrypt' => ['algorithm' => 'bcrypt'],
        'sodium' => ['algorithm' => 'sodium'],
    ]);

Although the example code above uses the array keys *auto*, *bcrypt* and
*sodium*, you can in fact use any valid array key: it's *these* array keys that
are used when obtaining a PasswordHasher from the ``PasswordHasherFactory``.

The value of the algorithm is important as this influences which password
hashing algorithm is used.

Currently supported hashing algorithms are::

* ``auto``
* ``plaintext``
* ``pbkdf2``
* ``bcrypt``
* ``sodium``
* ``argon2i``
* ``argon2id``

In addition, any other registered hashing algorithm can be used (such
as *sha512*).

Obtaining a PasswordHasher
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``PasswordHasherFactory`` implements the ``PasswordHasherFactoryInterface``
interface, it a single ``getPasswordHasher()`` method which takes one argument,
the key (string) of a configured password hasher::

    // Retrieve a password hasher by its name
    $passwordHasher = $factory->getPasswordHasher('common');

Hashing
~~~~~~~

The password hasher can then be used to hash a plain password::

    // Hash a plain password
    $hash = $passwordHasher->hash('plain'); // returns a bcrypt hash

Verifying Passwords
~~~~~~~~~~~~~~~~~~~

And lastly, the password hasher can be used to verify a given password matches
the hash::

    // Verify that a given plain password matches the hash
    $passwordHasher->verify($hash, 'wrong'); // returns false
    $passwordHasher->verify($hash, 'plain'); // returns true (valid)

.. toctree::
    :maxdepth: 1
    :glob:

    /components/password_hasher/*
    /password_hasher/*

.. _cryptographic hash function: https://en.wikipedia.org/wiki/Cryptographic_hash_function
