Hypercall tool to accompany Hyper-V blog series by Jaanus Kääp (@FoxHex0ne)

Currently available commands:
  !hc_env [environment]
    Can give info about in what environment the tool thinks it's running and allows to change it (hypervisor/kernel)

  !hc_list [hypercall number]
    Shows list of hypercalls, their handlers and names (if known). If hypercall number is provided, then shows only that

  !hc_filter [hypercall numbers to ignore, seperated by spaces]
    Injects int3 and additional snippet of machinecode to break before hypercalls but only for hypercalls not in the list
    Example: '!hv_filter 2 3' will start causing breaks with all hypercalls, except 2 and 3

  !hc_code {code}
    Decodes hypercall code value

  !hc_result {result}
    Decodes hypercall result value

  !hc
    Displays this info

  !hc_help
    Displays this info