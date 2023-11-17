# vHook - the simplest dll hacking library

I created this in 1 hour because i was bored, and i hope it will help the newbies understanding more how shit works, easily understandable and easy to use.

<img src="https://cdn.discordapp.com/attachments/1142220291859292411/1174944962853474394/image.png"/>

# Trampoline hook example
```cpp
int original_function() 
{
    std::cout << "Original Function\n";
    return 42;
}

int custom_function() 
{
    std::cout << "Custom Function\n";
    return 99;
}

int main() 
{
    uintptr_t original_function_address = reinterpret_cast<uintptr_t>(original_function);
    uintptr_t custom_function_address = reinterpret_cast<uintptr_t>(custom_function);
    uintptr_t hook_result = vhook::trampoline_hook(original_function_address, custom_function_address, 5);

    if (hook_result != 0) 
    {
        int result = original_function();
        std::cout << "Result: " << result << std::endl;

        VirtualFree(reinterpret_cast<void*>(hook_result), 0, MEM_RELEASE);
    } 
    else 
        std::cerr << "Hooking failed." << std::endl;

    return 0;
}
```

# IAT function hook example
```cpp
typedef void (*TestFunction)();
TestFunction original_test_function = []() { std::cout << "Original Test Function\n"; };

void custom_test_function() 
{
    std::cout << "Custom Test Function\n";
}

int main()
 {
    if (vhook::iat_hook("TestFunction", reinterpret_cast<vhook::orig_test_func>(vhook::custom_test_function))) 
        vhook::original_test_function();

    else
        std::cerr << "Hooking failed." << std::endl;
    
    return 0;
}
```

Note: this is only a preview atm, if people enjoy it, i will make a more complex version with a bunch of new features soon
