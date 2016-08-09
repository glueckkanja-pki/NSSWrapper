#pragma once

class BufferAppender
{
public:
	char *buffer;
	int size;

	BufferAppender(int iInitialSize)
	{
		size = 0;
		iAllocatedSize = iInitialSize;
		buffer = new char[iAllocatedSize];
	}

	~BufferAppender(void)
	{
		CHECK_NULL_AND_FREE(delete[], buffer);
	}

	// Check 
	void append(const char *data, int size)
	{
			// check whether the buffer is large enough to store the additonal data
		if (this->size + size > iAllocatedSize)
		{
			iAllocatedSize += iAllocatedSize/10 + 256 + size<<2;
			realloc(buffer, iAllocatedSize);
		}

		memcpy_s(buffer + this->size, iAllocatedSize - this->size, data, size);
		this->size += size;
	}

private:
	int iAllocatedSize;
};
