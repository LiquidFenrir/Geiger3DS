#pragma once

extern "C" {
#include <arm_cpu_ctx.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
}

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <list>
#include <vector>
#include <memory>
#include <string>
#include <span>
#include <set>
#include <map>
#include <utility>
#include <tuple>
#include <format>
#include <algorithm>

namespace recompiler {

struct cs_insn_deleter {
    void operator()(cs_insn* ptr)
    {
        cs_free(ptr, 1);
    }
};
using cs_insn_ptr = std::unique_ptr<cs_insn, cs_insn_deleter>;

#define ARM_CPU_PAGE_SIZE 0x1000
// a has to be a power of two
#define ALIGN_TO_NUM(n, a) (((n) + ((a) - 1u)) & -(a))
#define ALIGN_PAGE_NUM(n) ALIGN_TO_NUM(n, ARM_CPU_PAGE_SIZE)

struct Section {
    std::span<const u8_t> bytes;
    u32_t start_addr, end_addr;

    Section(std::span<const u8_t> bytes_in, u32_t start_addr_in) noexcept
        : bytes(bytes_in)
        , start_addr(start_addr_in)
        , end_addr(start_addr_in + bytes_in.size())
    { }

    u32_t length() const noexcept
    {
        return end_addr - start_addr;
    }

    bool is_in(u32_t addr, u32_t length = 0) const noexcept
    {
        return start_addr <= addr && (addr + length) < end_addr;
    }
};
struct Program {
    Section code_sec, rodata_sec, data_sec;
    u32_t start_addr;
    u32_t bss_size;

    Program(std::span<const u8_t> code_in, std::span<const u8_t> rodata_in, std::span<const u8_t> data_in, u32_t start_addr_in, u32_t bss_size_in) noexcept
        : code_sec(code_in, start_addr_in)
        , rodata_sec(rodata_in, ALIGN_PAGE_NUM(code_sec.end_addr))
        , data_sec(data_in, ALIGN_PAGE_NUM(rodata_sec.end_addr))
        , start_addr(start_addr_in)
        , bss_size(bss_size_in)
    { }

    bool is_in(u32_t addr, u32_t length = 0) const noexcept
    {
        return code_sec.is_in(addr, length)
            || rodata_sec.is_in(addr, length)
            || data_sec.is_in(addr, length)
            || (data_sec.end_addr <= addr && (addr + length) < (data_sec.end_addr + bss_size));
    }

    bool copy_from(u32_t addr, std::span<u8_t> into) const
    {
        const auto handle_sec = [](const Section& sec, u32_t addr, std::span<u8_t> into) {
            const u32_t off = addr - sec.start_addr;
            std::span<const u8_t> part = sec.bytes.subspan(off);
            std::copy_n(part.begin(), into.size(), into.begin());
            return true;
        };

        if(code_sec.is_in(addr, into.size()))
        {
            return handle_sec(code_sec, addr, into);
        }
        else if(rodata_sec.is_in(addr, into.size()))
        {
            return handle_sec(rodata_sec, addr, into);
        }
        else if(data_sec.is_in(addr, into.size()))
        {
            return handle_sec(data_sec, addr, into);
        }
        return false;
    }
};

struct VisitNode {
    u32_t start; // included
    u32_t end; // excluded
    explicit VisitNode(u32_t s, u32_t e) noexcept
        : start(s)
        , end(e)
    { }

    bool operator==(const VisitNode& rhs) const
    {
        return start == rhs.start && end == rhs.end;
    }

    u32_t length() const
    {
        return end - start;
    }
};
struct VisitList {
    VisitNode root;
    // list of ranges of valid instructions inside code
    // kept in order
    std::list<VisitNode> ranges;
    using value_type = decltype(ranges)::value_type;
    using reference = decltype(ranges)::reference;
    using const_reference = decltype(ranges)::const_reference;
    using iterator = decltype(ranges)::iterator;
    using const_iterator = decltype(ranges)::const_iterator;
    using difference_type = decltype(ranges)::difference_type;
    using size_type = decltype(ranges)::size_type;

    explicit VisitList(u32_t start, u32_t end)
        : root{start, end}
        , ranges{ {root} }
    { }
    explicit VisitList(u32_t length) : VisitList(0, length)
    { }

    // splits the node at `pos` into two nodes:
    // a low one from `pos->start` to `at_addr`, and a high one from `at_addr` to `pos->end`
    // returns an iterator to the low node (the high node can be accessed with a single increment)
    // the iterator to the split node is invalidated
    iterator split(iterator pos, u32_t at_addr)
    {
        assert(pos->start < at_addr && at_addr < pos->end);
        auto ret_it = ranges.insert(pos, {
            VisitNode(pos->start, at_addr),
            VisitNode(at_addr, pos->end),
        });
        ranges.erase(pos);
        return ret_it;
    }

    // erases the specified element
    // returns iterator following the removed element
    iterator erase(iterator pos) {
        return ranges.erase(pos);
    }

    // container compatibility methods
    iterator begin() { return ranges.begin(); }
    iterator end() { return ranges.end(); }
    const_iterator begin() const { return ranges.begin(); }
    const_iterator end() const { return ranges.end(); }
    const_iterator cbegin() const { return ranges.begin(); }
    const_iterator cend() const { return ranges.end(); }

    bool empty() const { return ranges.empty(); }
    std::size_t size() const { return ranges.size(); }
    std::size_t max_size() const { return ranges.max_size(); }

    bool operator==(const VisitList& rhs) const
    {
        return root == rhs.root && ranges == rhs.ranges;
    }
    void swap(VisitList& other)
    {
        std::swap(root, other.root);
        std::swap(ranges, other.ranges);
    }
};

#if 0
struct ValidNode {
    u32_t valid; // number of valid bytes
    u32_t skip; // number of invalid bytes following
    explicit ValidNode(u32_t v, u32_t s) noexcept
        : valid(v)
        , skip(s)
    { }

    bool operator==(const ValidNode& rhs) const
    {
        return valid == rhs.valid && skip == rhs.skip;
    }

    u32_t length() const
    {
        return valid + skip;
    }
};
struct ValidRange {
    ValidNode root;
    /*
     * assumptions:
     * only ranges.back() may have skip == 0 -> means the last range is fully valid
     * only ranges.front() may have valid == 0 -> means the first range is fully skipped
     * results:
     * second range may not exist, or starts valid
     * second to last range may not exist, or ends with skipping
     * during work:
     * if a range ends up with valid == 0, merge it with the previous range:
     * prev.skip += self.skip, delete self
     * if a range ends up with skip == 0, merge it with the next range:
     * self.valid += next.valid, self.skip = next.skip, delete next
     */
    std::list<ValidNode> ranges;
    using value_type = decltype(ranges)::value_type;
    using reference = decltype(ranges)::reference;
    using const_reference = decltype(ranges)::const_reference;
    using iterator = decltype(ranges)::iterator;
    using const_iterator = decltype(ranges)::const_iterator;
    using difference_type = decltype(ranges)::difference_type;
    using size_type = decltype(ranges)::size_type;

    explicit ValidRange(u32_t valid, u32_t skip)
        : root{valid, skip}
        , ranges{ {root} }
    { }
    explicit ValidRange(u32_t length) : ValidRange(0, length)
    { }

    // 0 <= start < root.length(): inclusive
    // 0 <= end <= root.length(): exclusive
    // start <= end
    // start == end -> 0 length -> noop
    void mark_valid(u32_t start, u32_t end)
    {
        assert(end <= root.length());
        if(start == end) return;
        for(auto it = ranges.begin(); it != ranges.end(); ++it)
        {
            /*
            - valid may be equal to start

            A: [[valid...start...end...skip...length]]
                -> nothing to do

            B: [[valid...start...skip...end...length]] -- skip after
                -> valid increases, skip decreases, to match end
                valid += skip - end;
                skip = old length - end; // >= 1
            B': [[valid...start...skip...end=length]] -- no skip, no next range (current range is last)
                -> valid increases to length, skip decreases to 0
                -> range is fully valid

            C: [[valid...start...skip...length next... end...]] -- more ranges covered, has no skip in current range
                -> end decreases by length
                -> merge into next range:
                    -> current range disappears, next range valid increases by current length
                -> go to appropriate next case of A/B/B'/C

            D: [[valid...skip...start...end...length]] -- skip before and after
                -> skip decreases to match start
                -> insert new range
                -> new range valid = end - start
                -> new range skip = old length - end (>= 1)
            D': [[valid...skip...start...end=length]] -- skip before, no next range (new range is last)
                -> skip decreases to match start
                -> insert new range
                -> new range valid = end - start
                -> new range skip = 0
                -> new range is fully valid

            E: [[valid...skip...start...length next... end...]] -- more ranges covered, has skip before start
                -> end decreases by start
                -> skip decreases to match start
                -> next range valid increases by old length - start
                -> start becomes starts of next range
                -> go to appropriate next case of A/B/B'/C
            */
            if(start < it->length())
            {
                if(start > it->valid)
                {
                    // start is inside the skip region without touching the valid
                    const auto current_range = *it;
                    const auto new_skip = current_range.skip - (start - current_range.valid);
                    it->skip = new_skip;
                    // 2 cases:
                    // start -> end fits entirely within the skip region
                    // start -> end finishes in next ranges' valid (maybe more than 1)
                    end -= current_range.valid;
                    if(end < current_range.skip)
                }

                // we need to start marking inside this range
                while(end)
                {
                    const auto current_range = *it;
                    if(end <= current_range.valid)
                    {
                        // end is already in a valid region: nothing to do
                        return;
                    }

                    end -= current_range.valid;
                    if(end < current_range.skip)
                    {
                        // range fully contains end, just increase its valid part, then done
                        it->valid += end;
                        it->skip -= end; // will be >= 1 after
                        return;
                    }
                    else /* if(end >= current_range.skip) */
                    {
                        // mark it for the next loop iteration math to work
                        end += current_range.valid;
                        // range is fully valid at least until end -> merges into next range
                        // next range valid count += current length (valid + skip)
                        // erase current range, it does not exist anymore
                        it = erase(it);
                        it->valid += current_range.length();
                    }
                }
            }
            else
            {
                // haven't started yet
                const auto length = it->length();
                start -= length;
                end -= length;
            }
        }
    }

    // erases the specified element
    // returns iterator following the removed element
    iterator erase(iterator pos) {
        return ranges.erase(pos);
    }
};
#endif

struct VisitTagged {
    VisitList unknown;
    VisitList is_arm;
    VisitList is_thumb;

    explicit VisitTagged(const VisitList& init)
        : unknown(init)
        , is_arm(init)
        , is_thumb(init)
    { }
};

VisitTagged analysis(const Program& program);

}
