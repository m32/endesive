#!/usr/bin/env python3
import io


def main():
    io.open('generated/smime-unsigned.txt', 'wt', encoding='utf-8').write('''\
Witam,

Fantastycznie, że zechciałeś popatrzeć na tę bibliotekę.
Mam nadzieję, że będzie dla Ciebie użyteczna.

Pozdrawiam,
Grzegorz Makarewicz
'''
                                                                )


main()
