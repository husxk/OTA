#include "file_reader.h"

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

void file_reader::handle_fatal_error(const char* operation) const
{
    fprintf(stderr, "Error: file_reader::%s failed for file '%s': %s\n", 
            operation, file_path.c_str(), strerror(errno));
    abort();
}

bool file_reader::load_file(const std::string& file_path)
{
    this->file_path = file_path;
    
    FILE* file = fopen(file_path.c_str(), "rb");
    if (!file)
    {
        handle_fatal_error("fopen");
    }
    
    file_handle.set(file);
    is_loaded = true;

    return true;
}

size_t file_reader::read_bytes(uint8_t* buffer, size_t max_bytes)
{
    if (!is_loaded || !file_handle.valid() || !buffer || eof_reached)
    {
        return 0;
    }
    
    size_t bytes_read = fread(buffer, 1, max_bytes, file_handle.get());
    
    if (bytes_read == max_bytes)
    {
        return bytes_read;
    }
    
    if (feof(file_handle.get()))
    {
        eof_reached = true;
        return bytes_read;
    }
    
    if (ferror(file_handle.get()))
    {
        handle_fatal_error("fread");
    }
    
    return bytes_read;
}