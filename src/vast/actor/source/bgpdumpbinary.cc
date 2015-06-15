#include "vast/actor/source/bgpdumpbinary.h"
#include "vast/concept/parseable/numeric/binary.h"
#include "vast/time.h"
#include "vast/address.h"
#include <cassert>
#include "vast/concept/parseable/vast/bgpbinary_parser.h"

namespace vast {
namespace source {

bgpdumpbinary::bgpdumpbinary(std::unique_ptr<io::input_stream> is)
  : byte_based<bgpdumpbinary>{"bgpdumpbinary-source", std::move(is)}
{
   bvector = this->import();
   counter = bvector.begin();
}

schema bgpdumpbinary::sniff(){}

void bgpdumpbinary::set(schema const& sch){}


result<event> bgpdumpbinary::extract()
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

  struct format t;
  auto p = bgpbinary_parser{};
  auto l = bvector.end();
  auto x = p.parse(counter, l, t);

  if(x.skipped)
  {
	return {};
  }

  funcCounter++;
  std::cout << "\n";
  std::cout << "+-----------------------------+\n";
  std::cout << "|           BGP Packet        |\n";
  std::cout << "+-----------------------------+\n";
  std::cout << "funcCounter: \t" << funcCounter << "\n";
  std::cout << "Timestamp: \t" << x.timestamp << "\n";
  std::cout << "ASN Nr: \t" << static_cast< int >(x.asnnr) <<"\n";
  std::cout << "Mode 1: \t" << static_cast< int >(x.m1) <<"\n";
  std::cout << "Mode 2: \t" << static_cast< int >(x.m2) <<"\n";

  if(funcCounter > 35)
  	assert(0==1);
  if(static_cast< int >(x.announce) == 12654)
  {
	x.annmode = "A";
	std::cout << "Announce: \t" << x.annmode <<"\n";	
	
  }	
  if(static_cast< int >(x.nag) == 49160)
  {
	x.nags = "NAG";
	std::cout << "NAG: \t\t" << x.nags <<"\n";
  }
  
  if(static_cast< int >(x.mode) == 521)
  {
	x.cmode = "IGP";
  	std::cout << "Mode: \t\t" << x.cmode << "\n";
  }
  else if(static_cast< int >(x.mode) == 515)
  {
	x.cmode = "INCOMPLETE";
  	std::cout << "Mode: \t\t" << x.cmode << "\n";
  }

  std::cout << "Source IP: \t";
  if(x.srcipv4.size() > 0)
  {
  	for(size_t i=0; i < x.srcipv4.size()-1; ++i)
  	{
		std::cout << static_cast< int >(x.srcipv4[i]) << ".";
  	} 
	std::cout << static_cast< int >(x.srcipv4[x.srcipv4.size()-1]) << "\n";
  }

  else if(x.srcipv6.size() > 0)
  {
	for(size_t i=0; i < x.srcipv6.size()-1; ++i)
  	{
		std::cout << std::hex << static_cast< int >(x.srcipv6[i]) << ":";
  	} 
	std::cout << std::hex << static_cast< int >(x.srcipv6[x.srcipv6.size()-1]) << "\n";
  }

  std::cout << "Paths: \t\t";
  for(size_t i=0; i < x.paths.size(); ++i)
  {
		std::cout << std::dec << static_cast<int>(x.paths[i]) << " ";
  } 
  std::cout << "\n";

  std::cout << "Next Hop: \t";
  if(x.nexthopv4.size() > 0)
  {
  	for(size_t i=0; i < x.nexthopv4.size()-1; ++i)
  	{
		std::cout << static_cast< int >(x.nexthopv4[i]) << ".";
  	} 
	std::cout << static_cast< int >(x.nexthopv4[x.nexthopv4.size()-1]) << "\n";

  	std::cout << "ASN: \t\t";
  	for(size_t i=0; i < x.asns.size(); ++i)
  	{
		std::cout << static_cast< int >(x.asns[i]) << ":" << static_cast<int>(x.asnsprt[i]) << " ";
  	} 
  	std::cout << "\n";
  }

  else if(x.nexthopv6.size() > 0)
  {
	for(size_t i=0; i < x.nexthopv6.size()-1; ++i)
  	{
		std::cout << std::hex << static_cast< int >(x.nexthopv6[i]) << ":";
  	} 
	std::cout << std::hex << static_cast< int >(x.nexthopv6[x.nexthopv6.size()-1]) << "\n";
  }
 
  std::cout << "Prefix: \t";
  if(x.prefixv4.size() > 0)
  {
  	for(size_t i= 0; i < x.prefixv4.size(); ++i)
  	{
		for(size_t j= 1; j < x.prefixv4[i].size() - 1; ++j)
  		{
			std::cout << static_cast<int>(x.prefixv4[i][j]) << ".";
  		}
		std::cout << static_cast<int>(x.prefixv4[i][x.prefixv4[i].size()-1]) << ".0";
		std::cout << " /" << static_cast<int>(x.prefixv4[i][0]) << ", ";
  	}
  	std::cout << "\n";
  }

  else if(x.prefixv6.size() > 0)
  {
  	for(size_t i= 0; i < x.prefixv6.size(); ++i)
  	{
		for(size_t j= 1; j < x.prefixv6[i].size() - 1; ++j)
  		{
			std::cout << std::hex << static_cast<int>(x.prefixv6[i][j]) << ":";
  		}
		std::cout << std::hex << static_cast<int>(x.prefixv6[i][x.prefixv6[i].size()-1]) << "::";
		std::cout << " /" << std::dec << static_cast<int>(x.prefixv6[i][0]) << ", ";
		
  	}
  	std::cout << "\n";
  }
  
  /*auto elems = util::split(this->line(), separator_);
  if (elems.size() < 5)
    return {};*/

 //time::point xy = time::now() - time.now() + x.timestamp;
 // xy = x.timestamp;
  //auto timestamp;
  //time::point xy = time:point{timestamp};

  //time::point xz = time::point{x.timestamp};
  //time::point{x.timestamp};
  //auto t = parse(timestamp, elems[1].first, elems[1].second);
 // if (! t)
  //  return {};

  //std::string update; // A,W,STATE,...
  //t = parse(update, elems[2].first, elems[2].second);
  //if (! t)
   // return {};

  //vast::address source_ip = vast::address(x.srcipv4);
  /*vast::address source_ip;
  t = parse(source_ip, elems[3].first, elems[3].second);
  if (! t)
    return {};

  count source_as;
  t = parse(source_as, elems[4].first, elems[4].second);
  if (! t)
    return {};

  record r;
  r.emplace_back(std::move(timestamp));
  r.emplace_back(std::move(source_ip));
  r.emplace_back(std::move(source_as));

  if ((update == "A" || update == "B") && elems.size() >= 14)
  {
    // announcement or routing table entry
    subnet prefix;
    t = parse(prefix, elems[5].first, elems[5].second);
    if (! t)
      return {};

    vast::vector as_path;
    count origin_as = 0;
    t = parse_origin_as(origin_as, as_path, elems[6].first, elems[6].second);
    if (! t)
      return {};

    std::string origin;
    t = parse(origin, elems[7].first, elems[7].second);
    if (! t)
      return {};

    vast::address nexthop;
    t = parse(nexthop, elems[8].first, elems[8].second);
    if (! t)
      return {};

    count local_pref;
    t = parse(local_pref, elems[9].first, elems[9].second);
    if (! t)
      return {};

    count med;
    t = parse(med, elems[10].first, elems[10].second);
    if (! t)
      return {};

    std::string community;
    if (elems[11].first != elems[11].second)
    {
      t = parse(community, elems[11].first, elems[11].second);
      if (! t)
        return {};
    }

    std::string atomic_aggregate;
    if (elems[12].first != elems[12].second)
    {
      t = parse(atomic_aggregate, elems[12].first, elems[12].second);
      if (! t)
        return {};
    }

    std::string aggregator;
    if (elems[13].first != elems[13].second)
    {
      t = parse(aggregator, elems[13].first, elems[13].second);
      if (! t)
        return {};
    }

    r.emplace_back(std::move(prefix));
    r.emplace_back(std::move(as_path));
    r.emplace_back(std::move(origin_as));
    r.emplace_back(std::move(origin));
    r.emplace_back(std::move(nexthop));
    r.emplace_back(std::move(local_pref));
    r.emplace_back(std::move(med));
    r.emplace_back(std::move(community));
    r.emplace_back(std::move(atomic_aggregate));
    r.emplace_back(std::move(aggregator));
    event e{{std::move(r), update == "A" ? announce_type_ : route_type_}};
    e.timestamp(timestamp);
    return std::move(e);
  }
  else if (update == "W" && elems.size() >= 6) // withdraw
  {
    subnet prefix;
    t = parse(prefix, elems[5].first, elems[5].second);
    if (! t)
      return {};

    r.emplace_back(std::move(prefix));
    event e{{std::move(r), withdraw_type_}};
    e.timestamp(timestamp);
    return std::move(e);
  }
  else if (update == "STATE" && elems.size() >= 7) // state change
  {
    std::string old_state;
    t = parse(old_state, elems[5].first, elems[5].second);
    if (! t)
      return {};

    std::string new_state;
    t = parse(new_state, elems[6].first, elems[6].second);
    if (! t)
      return {};

    r.emplace_back(std::move(old_state));
    r.emplace_back(std::move(new_state));
    event e{{std::move(r), state_change_type_}};
    e.timestamp(timestamp);
    return std::move(e);
  }*/
  return {};
  
}

} // namespace source
} // namespace vast
