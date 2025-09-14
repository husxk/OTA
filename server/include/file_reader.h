#pragma once
#include <string>
#include <vector>
#include <memory>
#include "file_wrapper.h"

class file_reader
{
public:
    file_reader() = default;
    ~file_reader() = default;

    bool load_file(const std::string& file_path);
    size_t read_bytes(uint8_t* buffer, size_t max_bytes);

    std::string get_file_path() const
    {
        return file_path;
    }

protected:
    std::string file_path;
    file_wrapper file_handle;
    bool is_loaded = false;
    bool eof_reached = false;

private:
    void handle_fatal_error(const char* operation) const;
};