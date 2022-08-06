#!/usr/bin/env python3
import json, argparse


def get_args():
    """args!!!"""
    parser = argparse.ArgumentParser(description="Generate CPP for TamperingSyscalls")
    parser.add_argument("functions", help="Comma seperated list of NTDLL Functions")
    args = parser.parse_args()
    return args


def get_prototypes(target_functions: list):
    """read prototypes.json, thanks to https://github.com/klezVirus/SysWhispers3/blob/master/data/prototypes.json"""
    targets = {}
    with open("data/prototypes.json") as f:
        data = json.load(f)
        if target_functions == "all":
            targets = data
        else:
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

        struct = "typedef struct {\n\r"
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

        typedef = f"typedef {function_data['type']} (NTAPI* type{function_name})(\n\r"

        for idx, param in enumerate(params):
            if idx == len(params) - 1:
                typedef += f"    {param['type']:<25}{param['name']}\n"
            else:
                typedef += f"    {param['type']:<25}{param['name']},\n"
        else:
            typedef += ");\n\n"

        code += typedef

    return f"{code}\n"


def build_definitions(data: dict):
    """the initial definition"""
    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        code += f"type{function_name} f{function_name};\n{function_name}Args p{function_name}Args;\n\n"

    return f"{code}\n"


def build_function_case(data: dict):
    """build the function case"""

    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        args = []

        invoke = f"case {function_name.upper()}_ENUM:\n"
        invoke += f"    f{function_name} = (type{function_name})FunctionAddress;\n"

        for idx, param in enumerate(params):
            if idx <= 3:
                args.append("NULL")
            else:
                args.append(f"p{function_name}.{param['name']}")

            joined = ", ".join(args)

        invoke += f"    status = f{function_name}({joined});\n    break;\n\n"

        code += invoke

    return f"{code}\n"


def build_oneshot_case(data: dict):
    """set the first 4 args"""

    code = ""

    for function_name, function_data in data.items():
        params = function_data["params"]

        mappings = {0: "R10", 1: "Rdx", 2: "R8", 3: "R9"}
        case = f"case {function_name.upper()}_ENUM:\n"
        for idx in range(0, 4):
            if idx >= len(params):
                break
            register = mappings[idx]
            case += f"    ExceptionInfo->ContextRecord->{register} =\n    (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[StatePointer].arguments))->{params[idx]['name']};\n    break;\n\n"
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

    arg_struct = build_arg_struct(data)
    typedef = build_typedef(data)
    definitions = build_definitions(data)
    initial_case = build_function_case(data)
    oneshot = build_oneshot_case(data)
    statearray = build_state_arrays(data)
    print(arg_struct)
    print()
    print(typedef)
    print()
    print(definitions)
    print()
    print(initial_case)
    print()
    print(oneshot)
    print()
    print(statearray)


if __name__ == "__main__":
    main()
