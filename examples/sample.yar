rule Ransom_Note_Generic
{
    strings:
        $a = "your files have been encrypted"
        $b = "bitcoin"
        $c = /\.onion\b/ nocase
    condition:
        2 of them
}
