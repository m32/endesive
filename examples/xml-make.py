#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io


def main():
    io.open('xml.xml', 'wt', encoding='utf-8').write('''\
<?xml version="1.0" encoding="UTF-8"?>
<Deklaracja
        xmlns:etd="http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2016/01/25/eD/DefinicjeTypy/"
        xmlns="http://crd.gov.pl/wzor/2016/08/05/3412/"
>
    <Naglowek>
        <KodFormularza kodSystemowy="VAT-7 (17)" kodPodatku="VAT" rodzajZobowiazania="Z" wersjaSchemy="1-0E">VAT-7
        </KodFormularza>
        <WariantFormularza>17</WariantFormularza>
        <CelZlozenia poz="P_7">1</CelZlozenia>
        <Rok>2017</Rok>
        <Miesiac>2</Miesiac>
        <KodUrzedu>3215</KodUrzedu>
    </Naglowek>
    <Podmiot1 rola="Podatnik">
        <etd:OsobaNiefizyczna>
            <etd:NIP>7791011327</etd:NIP>
            <etd:PelnaNazwa>Nazwa firmy</etd:PelnaNazwa>
            <etd:REGON>630303023</etd:REGON>
        </etd:OsobaNiefizyczna>
    </Podmiot1>
    <PozycjeSzczegolowe>
        <P_10>0</P_10>
        <P_11>3108</P_11>
        <P_12>3108</P_12>
        <P_13>0</P_13>
        <P_14>0</P_14>
        <P_15>998293</P_15>
        <P_16>49915</P_16>
        <P_17>901697</P_17>
        <P_18>72135</P_18>
        <P_19>3334214</P_19>
        <P_20>766869</P_20>
        <P_21>3177289</P_21>
        <P_22>187401</P_22>
        <P_23>44326</P_23>
        <P_24>8864</P_24>
        <P_25>0</P_25>
        <P_26>0</P_26>
        <P_27>0</P_27>
        <P_28>0</P_28>
        <P_29>66801</P_29>
        <P_30>15364</P_30>
        <P_31>0</P_31>
        <P_32>0</P_32>
        <P_33>0</P_33>
        <P_34>0</P_34>
        <P_35>0</P_35>
        <P_36>0</P_36>
        <P_37>0</P_37>
        <P_38>0</P_38>
        <P_39>0</P_39>
        <P_40>8713129</P_40>
        <P_41>913147</P_41>
        <P_42>512089</P_42>
        <P_43>54480</P_43>
        <P_44>12531</P_44>
        <P_45>8152972</P_45>
        <P_46>1279013</P_46>
        <P_47>0</P_47>
        <P_48>0</P_48>
        <P_49>-138</P_49>
        <P_50>1380</P_50>
        <P_51>1804875</P_51>
        <P_52>0</P_52>
        <P_53>0</P_53>
        <P_54>0</P_54>
        <P_55>0</P_55>
        <P_56>891728</P_56>
        <P_57>0</P_57>
        <P_58>0</P_58>
        <P_59>0</P_59>
        <P_60>0</P_60>
        <P_61>891728</P_61>
        <P_66>2</P_66>
        <P_67>2</P_67>
        <P_68>2</P_68>
        <P_73>914842496</P_73>
        <P_74>2017-05-09</P_74>
    </PozycjeSzczegolowe>
    <Pouczenia>1</Pouczenia>
</Deklaracja>
'''
                                                                )


main()
