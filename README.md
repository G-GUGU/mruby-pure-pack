Puck and Unpack methods
=========

Add Array#pack and String#unpack methods on MRuby. Almost all code is written by ruby itself.
20 to 100 times slower than original CRuby method.

## Support template

Same as CRuby but not support 'U'(UTF-8), 'p' 'P'(pointer) and 'M'(q-printable) yet.

## License

mruby-pure-pack is released under the [MIT License](MITL).
