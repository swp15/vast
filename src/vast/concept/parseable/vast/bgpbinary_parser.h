#ifndef VAST_CONCEPT_PARSEABLE_VAST_JSON_H
#define VAST_CONCEPT_PARSEABLE_VAST_JSON_H

#include <map>
#include <string>
#include <vector>
#include "vast/access.h"
#include "vast/concept/parseable/vast/address.h"


namespace vast {

using namespace vast::util;

struct bgpbinary_parser : parser<bgpbinary_parser>
{
  struct format
  {
	uint32_t timestamp;
	uint32_t asnnr;
	uint16_t announce;
	uint8_t m1;
	uint8_t m2;
	uint16_t nag;
	uint16_t mode;
	uint32_t length;
	bool skipped;
	std::string annmode;
	std::string nags;
  	std::string cmode;
	std::vector<uint8_t> srcipv4;
	std::vector<uint16_t> srcipv6;
	std::vector<uint32_t> paths;
	std::vector<uint8_t> nexthopv4;
	std::vector<uint16_t> nexthopv6;
	std::vector<uint16_t> asns;	
	std::vector<uint16_t> asnsprt;	
	std::vector<std::vector<uint16_t>> prefixv6;
	std::vector<std::vector<uint8_t>> prefixv4;
  };

  template <typename Iterator>
  bool parse(Iterator& f, Iterator const& l, unused_type) const
  {
    //static auto p = make();
    //return p.parse(f, l, unused);
  }

  template <typename Iterator, typename Attribute>
  format body(Iterator& f, Iterator const& l, Attribute& a) const
  {
	format r;
	uint32_t t32 = 0;
	uint16_t t16 = 0;
	uint8_t t8 = 0;

	/*Timestamp*/
	parsers::b32be.parse(f, f + 4, t32);
	r.timestamp = t32;

	/*Type*/
	parsers::b16be.parse(f, f + 2, t16);

	/*Subtype*/
	parsers::b16be.parse(f, f + 2, t16);

	/*Length*/
	t32 = 0;
 	parsers::b32be.parse(f, f + 4,t32);
	r.length = t32;
	uint32_t length = t32;
	
	if(length < 70 || length > 130)
	{
		for (int i=0; i < length;++i)
		{
			parsers::b8be.parse(f, f + 1,t8);	
		}
		r.skipped = true;
		return r;
	}

	/*ASN NUMBER*/
	t32 = 0;
 	parsers::b32be.parse(f, f + 4,t32);
	length = length - 4;
	r.asnnr = t32;

	/*Mode 1*/
	t8 = 0;
	parsers::b8be.parse(f, f + 1, t8);
	length = length - 1;
	r.m1 = t8;

	/*Mode 2*/
	t8 = 0;
	parsers::b8be.parse(f, f + 1, t8);
	length = length - 1;
	r.m2 = t8;

	/*Announce*/
	t16 = 0;
	parsers::b16be.parse(f, f + 2, t16);
	length = length - 2;
	r.announce = t16;

	/*IP VERSION*/
	t32 = 0;
	parsers::b32be.parse(f, f + 4, t32);
	length = length - 4;
	uint32_t ipvrs = t32;

	/*IPv4*/
	uint8_t it = 1;
	if(ipvrs == 1)
	{
			
		while(it <= 4)
		{
			it++;
			parsers::b8be.parse(f, f + 1, t8);
			length = length - 1;
			r.srcipv4.push_back(t8);	
			t8 = 0;
		}

		/*undeclared 2*/
		for(auto i = 0; i < 8; ++i)
		{
			parsers::b32be.parse(f, f + 4, t32);
			length = length - 4;
		}
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;

		/*PATH LENGTH*/
		t8 = 0;
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
		uint8_t pathlen = (t8 - 2) / 4;	

		/*Mode*/
		t16 = 0;
		parsers::b16be.parse(f, f + 2, t16);
		length = length - 2;
		r.mode = t16;
	
		it = 0;
		while(it < pathlen)
		{
			t32 = 0;
			parsers::b32be.parse(f, f + 4, t32);
			length = length - 4;
			r.paths.push_back(t32);	
			it++;
		}

		/* undeclared 5*/
		parsers::b16be.parse(f, f + 2, t16);
		length = length - 2;

		/*Next Hop Length*/
		t8 = 0;
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
		uint8_t nxthoplen = t8;

		/*Next Hop*/
		it = 0;
		while(it < nxthoplen)
		{
			it++;
			t8 = 0;
			parsers::b8be.parse(f, f + 1, t8);
			length = length - 1;
			r.nexthopv4.push_back(t8);	
		}

		/*NAG*/
		t16 = 0;
		parsers::b16be.parse(f, f + 2, t16);
		length = length - 2;
		r.nag = t16;

		/*ASN Field Length*/
		t8 = 0;
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
		uint8_t asnlen = t8;

		/*ASN*/
		it = 0;
		while(it < asnlen)
		{
			t16 = 0;
			parsers::b16be.parse(f, f + 2, t16);
			length = length - 2;
			r.asns.push_back(t16);	
			t16 = 0;
			parsers::b16be.parse(f, f + 2, t16);
			length = length - 2;
			r.asnsprt.push_back(t16);
			it = it + 4;
		}

		/*Prefix*/
		it = 0;
		std::vector<uint8_t> subprefix; 
		while(it < length)
		{
			subprefix.clear();
			for(int i = 0; i < 4; ++i)
			{
				t8 = 0;
				parsers::b8be.parse(f, f + 1, t8);
				subprefix.push_back(t8);
				it++;
			}
			r.prefixv4.push_back(subprefix);
		}
	}

	//IPv6
	else if(ipvrs == 2)
	{
		//Source IPv6
		it = 0;
		while(it < 8)
		{
			t16 = 0;
			parsers::b16be.parse(f, f + 2, t16);
			length = length - 2;
			r.srcipv6.push_back(t16);	
			it++;
		}

		for(auto i = 0; i < 11; ++i)
		{
			parsers::b32be.parse(f, f + 4, t32);
			length = length - 4;
		}
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
	
		//Next Hop Length
		t8 = 0;
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
		uint8_t nxthoplen = t8;

		//Next Hop
		it = 0;
		while(it < nxthoplen)
		{
			t16 = 0;
			parsers::b16be.parse(f, f + 2, t16);
			length = length - 2;
			r.nexthopv6.push_back(t16);
			it = it+2;	
		}

		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;

		/*Prefix*/
		std::vector<uint16_t> subprefix; 
		bool delimiter = false;
		uint8_t prefixlen = 0;
		int Counter = 0;

	while(!delimiter)
	{
		t16 = 0;
		t8 = 0;
		parsers::b16be.parse(f, f + 2, t16);
		parsers::b8be.parse(f, f + 1, t8);
		f = f - 3;			

		if (static_cast<int>(t16) == 16385 && static_cast<int>(t8) == 1)
		{
			delimiter = true;
		}
		else 
		{
			t8 = 0;
			parsers::b8be.parse(f, f + 1, t8);
			prefixlen = t8 / 8;
			subprefix.push_back(t8);

			while (prefixlen > 0)
			{
				if (prefixlen == 1)
				{
					t16 = 0;
					t8 = 0;
					parsers::b8be.parse(f, f + 1, t8);
					t16 = t8 << 8;
					subprefix.push_back(t16);
					prefixlen--;
				}

				else
				{
					t16 = 0;
					parsers::b16be.parse(f, f + 2, t16);
					subprefix.push_back(t16);
					prefixlen = prefixlen - 2;
				}
			}

			r.prefixv6.push_back(subprefix);
			subprefix.clear();
		}
	}

		for(int i = 0; i < 4; ++i)
		{
			parsers::b16be.parse(f, f + 2, t16);	
		}


		//Path Length
		t8 = 0;
		parsers::b8be.parse(f, f + 1, t8);
		length = length - 1;
		uint8_t pathlen = t8;
		
		// Paths
		it = 0;
		while(it < pathlen)
		{
			t32 = 0;
			parsers::b32be.parse(f, f + 4, t32);
			length = length - 4;
			r.paths.push_back(t32);	
			it++;
		}
	}
	
	return r;
  }

  template <typename Iterator, typename Attribute>
  format parse(Iterator& f, Iterator const& l, Attribute& a) const
  {
	auto r = body(f, l, a);
	return r;
  }
};

template <>
struct parser_registry<bgpbinary_parser::format>
{
  using type = bgpbinary_parser;
};

} // namespace vast

#endif
