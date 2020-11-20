// Imported from NuevoMatch:
// https://github.com/acsl-technion/nuevomatch

#include <vector>
#include <list>
#include <string>
#include <fstream>
#include <sstream>

/**
 * @brief Copy a list to array
 * @tparam T The vector type
 * @param vec The vector
 * @return A new allocated array with data
 */
template <typename T>
T* list_to_array(std::list<T> vec) {
    T* output = new T[vec.size()];
    std::copy(vec.begin(), vec.end(), output);
    return output;
}

/**
 * @brief Simulates an input packet when using packet-traces
 */
typedef struct trace_packet{
    std::vector<uint32_t> header;
    uint32_t match_priority;

    /**
     * @brief Returns a pointer to the header values
     */
    const uint32_t* get() const { return &header[0]; }

    /**
     * @brief Returns a string representation of this
     */
    std::string to_string() const;
} trace_packet;

/**
 * @brief Returns a string representation of this
 */
std::string trace_packet::to_string() const {
  std::stringstream ss;
	for (auto f : this->header) {
		ss << f << "\t";
	}
	ss << this->match_priority;
	return ss.str();
}

/**
 * @brief Reads a textual trace file into memory
 * @param[in] trace_filename The textual trace filename
 * @param[in] indices A vector of custom fields to look at
 * @param[out] num_of_packets The number of packet in trace
 * @returns An array of trace packet headers, or NULL in case of an error
 */
trace_packet* read_trace_file(const char* trace_filename, const std::vector<uint32_t>& indices, uint32_t* num_of_packets) {
	// Open file
  std::fstream fs;
	fs.open(trace_filename, std::fstream::in);

	// Check whether file exists
	if (!fs.good()) {
		fprintf(stderr, "cannot open file for reading trace: file does not exist: %s\n", trace_filename);
    exit(1);
	}

	// Output list
	std::list<trace_packet> output;

	trace_packet packet;
	char buffer[25], c;
	int current = 0;

	// Flags
	bool field_end = false, check_packet = false;

	do {
		// Get char
		c = fs.get();

		// In case of number
		if ((c >= '0') && (c <= '9')) {
			buffer[current++]=c;
		}
		// In case of field delimiter
		else if ( (c == ' ') || (c == '\t')) {
			field_end = true;
		}
		// In case of new line or EOF
		else if ((c == '\n') || (fs.eof())) {
			field_end = true;
			check_packet = true;
		}

		// The current field was ended
		if (field_end) {
			if (current > 0) {
				buffer[current++] = '\0';
				packet.header.push_back(atoi(buffer));
			}
			field_end = false;
			current = 0;
		}

		// The whole packet as ended
		if (check_packet) {
			// In case the current packet is not empty
			if (packet.header.size() > 0) {

				// Remove last header, set as match index
				packet.match_priority = packet.header.back();
				packet.header.pop_back();

				// Shuffle header according to indices
				if (indices.size() > 0) {
					std::vector<uint32_t> new_header(indices.size());
					for (uint32_t i=0; i<indices.size(); ++i) {
						if (indices[i] > packet.header.size()) {
							fprintf(stderr, "Cannot extract field %d from trace packet, as it has only %d fields\n",
									indices[i], packet.header.size());
              exit(1);
						}
						new_header[i] = packet.header[indices[i]];
					}
					packet.header = new_header;
				}

				// Add packet to output list
				output.push_back(std::move(packet));
			}
			check_packet = false;
		}
	} while (!fs.eof());

	*num_of_packets = output.size();
	return list_to_array(output);
}
