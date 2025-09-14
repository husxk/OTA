#pragma once
#include <cstdio>

// RAII wrapper for FILE* to ensure automatic file closure
// Prevents resource leaks and provides exception safety
class file_wrapper
{
public:
    file_wrapper()
    : file(nullptr)
    {
    }

    explicit file_wrapper(FILE* file_ptr)
    : file(file_ptr)
    {
    }

    ~file_wrapper()
    {
        if (file)
        {
            fclose(file);
        }
    }

    FILE* get() const
    {
        return file;
    }

    void set(FILE* file_ptr)
    {
        if (file)
        {
            fclose(file);
        }

        file = file_ptr;
    }

    bool valid() const
    {
        return file != nullptr;
    }

private:
    FILE* file;
};
