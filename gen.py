#!/usr/bin/env python3
import json, argparse


def get_args():
    """args!!!"""
    parser = argparse.ArgumentParser(description="Generate CPP for TamperingSyscalls")
    parser.add_argument("functions", help="Comma seperated list of NTDLL Functions")
    parser.add_argument(
        "--output",
        "-o",
        required=False,
        default="TamperingSyscalls",
        help="Path to output file",
    )
    args = parser.parse_args()
    return args


def get_prototypes(target_functions: list):
    """read prototypes.json, thanks to https://github.com/klezVirus/SysWhispers3/blob/master/data/prototypes.json"""
    targets = {}
    with open("data/prototypes.json") as f:
        data = json.load(f)
        for function in data.keys():
            if function in target_functions:
                targets[function] = data[function]
    return targets


def has_minimum_args(params: list):
    """if there are <= 4 params, then it doesnt need setup"""

    # if there are 4 or more args, then setup can continue
    if len(params) >= 4:
        return True
    else:
        # else it will hit the default case
        return False


def build_arg_struct(data: dict):
    """build the arguments as a struct"""

    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        struct = "typedef struct {\n"
        for param in params:
            struct += f"    {param['type']:<27}{param['name']};\n"
        else:
            struct += f"}} {function_name}Args;\n"

        code += f"{struct}\n"
    return code


def build_typedef(data: dict):
    """build the typedef for the function"""

    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        typedef = f"typedef {function_data['type']} (NTAPI* type{function_name})(\n"

        for idx, param in enumerate(params):
            if idx == len(params) - 1:
                typedef += f"    {param['type']:<25}{param['name']}\n"
            else:
                typedef += f"    {param['type']:<25}{param['name']},\n"
        else:
            typedef += ");\n"

        code += typedef

    return f"{code}\n"


def build_arg_defs(data: dict):
    """the initial definition"""
    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        code += f"{function_name}Args p{function_name}Args;\n"

    return f"{code}\n"


def build_func_defs(data: dict):
    """the function defs"""
    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]
        args = ", ".join([f"{param['type']} {param['name']}" for param in params])
        code += f"{function_data['type']} p{function_name}({args});\n"
    return f"{code}\n"


def build_enum_defs(data: dict):
    """the function defs"""
    code = "enum\n{\n    "

    enum = [function_name.upper() + "_ENUM" for function_name in data.keys()]

    enum[0] = enum[0].replace(enum[0], f"{enum[0]} = 0")

    code += ",\n    ".join(enum)

    code += "\n};\n"

    return f"{code}\n"


def build_function_call(function_name, params: list):
    """build the function case"""

    code = ""

    args = []

    for idx, param in enumerate(params):
        if idx <= 3:
            args.append("NULL")
        else:
            args.append(f"p{function_name}Args.{param['name']}")

        joined = ", ".join(args)

    return f"    status = f{function_name}({joined});\n"


def build_oneshot_case(data: dict):
    """set the first 4 args"""

    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        mappings = {0: "R10", 1: "Rdx", 2: "R8", 3: "R9"}
        case = f"{' ' * 20}case {function_name.upper()}_ENUM:\n"
        for idx in range(0, 4):
            if idx >= len(params):
                break
            register = mappings[idx]
            case += f"{' ' * 24}ExceptionInfo->ContextRecord->{register} = (DWORD_PTR)(({function_name}Args*)(StateArray[EnumState].arguments))->{params[idx]['name']};\n"

        case += f"{' ' * 24}break;\n"
        code += case

    return f"{code}\n"


def build_state_arrays(data: dict):
    """set the state arrays"""
    code = "STATE StateArray[] = {\n"

    functions_total = len(data.keys())
    idx = 0

    for function_name, function_data in data.items():
        idx += 1
        params = function_data["params"]

        if idx >= functions_total:
            state = f"    {{ {function_name.upper()}_ENUM, &p{function_name}Args }}\n"
        else:
            state = f"    {{ {function_name.upper()}_ENUM, &p{function_name}Args }},\n"
        code += state
    code += "};"

    return f"{code}\n"


def build_function_wrapper(data: dict):
    """set the state arrays"""
    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]
        args = ", ".join([f"{param['type']} {param['name']}" for param in params])
        wrapper = f"{function_data['type']} p{function_name}({args}) {{\n"
        wrapper += "    LPVOID FunctionAddress;\n    NTSTATUS status;\n\n"
        wrapper += f"    hash( {function_name} );\n"
        wrapper += (
            f"    FunctionAddress = GetProcAddrExH( hash{function_name}, hashNTDLL );\n"
        )
        wrapper += f"    type{function_name} f{function_name};\n\n"

        for param in params:
            wrapper += f"    p{function_name}Args.{param['name']} = {param['name']};\n"

        wrapper += f"    f{function_name} = (type{function_name})FunctionAddress;\n\n"
        wrapper += f"    EnumState = {function_name.upper()}_ENUM;\n\n"
        wrapper += f"    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );\n"

        wrapper += f"{build_function_call(function_name, params)}"

        wrapper += "    return status;\n}\n\n"
        code += wrapper

    return code


def gen_main(file_name: str):
    """generate main.cpp"""
    return f'#include "{file_name}.h"\n\nint main(){{\n    SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );\n    /* Code Here */\n}}'


def main():
    """Entry!"""
    args = get_args()

    functions = []

    if "," in args.functions:
        functions = args.functions.split(",")
    else:
        functions = args.functions

    data = get_prototypes(functions)

    if data == None:
        return

    src = ""

    arg_struct = build_arg_struct(data)
    function_typedef = build_typedef(data)
    arg_defs = build_arg_defs(data)
    func_defs = build_func_defs(data)
    enum_defs = build_enum_defs(data)
    statearray = build_state_arrays(data)
    oneshot = build_oneshot_case(data)
    wrapper = build_function_wrapper(data)

    with open("data/template.cpp", "r") as f:
        src = f.read()
        src = src.replace("$ONESHOT_CASE$", oneshot)
        src = src.replace("$WRAPPER_FUNCTIONS$", wrapper)
        src = src.replace("$FILE_NAME$", f"{args.output}.h")

    with open(f"{args.output}.cpp", "w") as f:
        f.write(src)
        print(f"[+] Wrote: {args.output}.cpp!")

    with open("data/template.h", "r") as f:
        src = f.read()
        src = src.replace("$ARG_TYPEDEFS$", arg_struct)
        src = src.replace("$FUNCTION_DEFS$", function_typedef)
        src = src.replace("$ARG_DEFS$", arg_defs)
        src = src.replace("$FUNC_DEFS$", func_defs)
        src = src.replace("$ENUM_DEFS$", enum_defs)
        src = src.replace("$STATE_ARRAY$", statearray)
        src = src.replace("$ONESHOT_CASE$", oneshot)
        src = src.replace("$WRAPPER_FUNCTIONS$", wrapper)

    with open(f"{args.output}.h", "w") as f:
        f.write(src)
        print(f"[+] Wrote: {args.output}.h!")

    with open("main.cpp", "w") as f:
        print(f"[+] Wrote: main.cpp!")
        f.write(gen_main(args.output))


if __name__ == "__main__":
    main()
