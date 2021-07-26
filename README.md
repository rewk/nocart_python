# nocart_python

Python port of the nocart tool from Kevin Thacker.

http://www.cpcwiki.eu/index.php/Nocart

## Description

This program can be used to create a .cpr file from a .dsk file, to be used on a GX-4000.
(With action 'create')

It can also check an existing .cpr file ('check').

It was mainly done because I wanted to understand how nocart worked.

The patched roms are the ones provided by the original nocart tool.

## Getting Started

### Installing

This requires at least Python 3.8.

It was made as a standalone python script, only requiring the directory patched_roms.

It doesn't require to be installed as a python package.


### Executing program

```
./nocart.py source.dsk target.cpr --command 'run"disc"'
```

## Authors

Mathieu CUNY (therewk)

## Version History

* 0.1
    * A working nocart.py, but not as complete as the original one.

## License

This project is licensed under the MIT License - see the LICENSE.txt file for details

## Acknowledgments

* [nocart](http://www.cpcwiki.eu/index.php/Nocart)
