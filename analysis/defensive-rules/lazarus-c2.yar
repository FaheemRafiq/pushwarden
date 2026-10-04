// pushwarden:allow-signatures
rule Lazarus_Contagious_Interview_C2 {
    meta:
        description = "Detects Lazarus Group Contagious Interview blockchain C2 malware"
        author = "PushWarden"
        date = "2026-08-21"
        reference = "https://github.com/FaheemRafiq/pushwarden"
        severity = "critical"
        tags = "lazarus, malware, blockchain, c2, contagious-interview"

    strings:
        $literal1 = "rmcej%otb%" ascii
        $literal2 = "global['!']='8-270-2'" ascii
        $literal3 = "global['!']='4-1928'" ascii
        $literal4 = "global['_V']='A4-1928'" ascii
        $literal5 = "global['!']='10-83-10'" ascii
        $literal6 = "global['!']='A10-010'" ascii
        $literal7 = "global['!']='A10-2340'" ascii

        $marker1 = /global\['!'\]\s*=\s*'[A-Z0-9-]{4,}'/ ascii
        $marker2 = /global\['_V'\]\s*=\s*'[A-Z0-9-]{4,}'/ ascii
        $marker3 = /\$_1e42/ ascii
        $marker4 = /global\['r'\]\s*=\s*require/ ascii

        $payload1 = "atob(process.env" ascii
        $payload2 = "eval(atob" ascii
        $payload3 = "global['r']=require" ascii

        $obfuscation1 = "(function(_0x" ascii
        $obfuscation2 = "_0x240a" ascii
        $obfuscation3 = "parseInt(_0x" ascii

        $blockchain1 = "eth_blockNumber" ascii
        $blockchain2 = "eth_getTransactionByHash" ascii
        $blockchain3 = "eth_getBlockByNumber" ascii

        $c2_header1 = "Sec-V" ascii
        $c2_header2 = "x-payload" ascii

        $propagation1 = "temp_auto_push.bat" ascii
        $propagation2 = "config.bat" ascii
        $propagation3 = "auto_push.bat" ascii

    condition:
        (
            any of ($literal*) or
            2 of ($marker*) or
            ($payload1 and $obfuscation1) or
            ($payload2 and $obfuscation1) or
            (2 of ($blockchain*) and any of ($c2_header*)) or
            any of ($propagation*) or
            ($marker3 and $obfuscation2 and $blockchain1)
        ) and filesize < 100KB
}

rule Lazarus_C2_Config_Injection {
    meta:
        description = "Detects config files with hidden Lazarus payloads"
        author = "PushWarden"
        severity = "critical"

    strings:
        $config1 = "postcss.config" ascii
        $config2 = "tailwind.config" ascii
        $config3 = "eslint.config" ascii
        $config4 = "next.config" ascii
        $config5 = "vite.config" ascii
        $config6 = "webpack.config" ascii
        $config7 = "babel.config" ascii
        $config8 = "jest.config" ascii
        $config9 = "svelte.config" ascii
        $config10 = "nuxt.config" ascii

        $malware = "atob(process.env" ascii

    condition:
        any of ($config*) and $malware and filesize > 1024
}

rule Lazarus_Propagation_Scripts {
    meta:
        description = "Detects Lazarus propagation batch scripts"
        author = "PushWarden"
        severity = "critical"

    strings:
        $bat1 = "temp_auto_push.bat" ascii nocase
        $bat2 = "temp_interactive_push.bat" ascii nocase
        $bat3 = "config.bat" ascii nocase
        $bat4 = "auto_push.bat" ascii nocase

        $git_push = "git push" ascii nocase
        $git_amend = "git commit --amend" ascii nocase
        $git_force = "git push --force" ascii nocase

    condition:
        any of ($bat*) and any of ($git_push, $git_amend, $git_force)
}
