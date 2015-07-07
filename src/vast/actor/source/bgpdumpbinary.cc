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
  std::vector<type::record::field> fields;
  fields.emplace_back("timestamp", type::time_point{});
  fields.emplace_back("source_ip", type::address{});
  fields.emplace_back("source_as", type::count{});
  fields.emplace_back("prefix", type::subnet{});
  fields.emplace_back("as_path", type::vector{type::count{}});
  fields.emplace_back("origin_as", type::count{});
  fields.emplace_back("origin", type::string{});
  fields.emplace_back("nexthop", type::address{});
  fields.emplace_back("local_pref", type::count{});
  fields.emplace_back("med", type::count{});
  fields.emplace_back("community", type::string{});
  fields.emplace_back("atomic_aggregate", type::string{});
  fields.emplace_back("aggregator", type::string{});
  announce_type_ = type::record{fields};
  announce_type_.name("bgpdump::announcement");

  route_type_ = type::record{std::move(fields)};
  route_type_.name("bgpdump::routing");

  std::vector<type::record::field> withdraw_fields;
  withdraw_fields.emplace_back("timestamp", type::time_point{});
  withdraw_fields.emplace_back("source_ip", type::address{});
  withdraw_fields.emplace_back("source_as", type::count{});
  withdraw_fields.emplace_back("prefix", type::subnet{});
  withdraw_type_ = type::record{std::move(withdraw_fields)};
  withdraw_type_.name("bgpdump::withdrawn");

  std::vector<type::record::field> state_change_fields;
  state_change_fields.emplace_back("timestamp", type::time_point{});
  state_change_fields.emplace_back("source_ip", type::address{});
  state_change_fields.emplace_back("source_as", type::count{});
  state_change_fields.emplace_back("old_state", type::count{});
  state_change_fields.emplace_back("new_state", type::count{});
  state_change_type_ = type::record{std::move(state_change_fields)};
  state_change_type_.name("bgpdump::state_change");
}

schema bgpdumpbinary::sniff()
{
  schema sch;
  sch.add(announce_type_);
  sch.add(route_type_);
  sch.add(withdraw_type_);
  sch.add(state_change_type_);
  return sch;
}

void bgpdumpbinary::set(schema const& sch)
{  
  if (auto t = sch.find_type(announce_type_.name()))
  {
    if (congruent(*t, announce_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      announce_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(route_type_.name()))
  {
    if (congruent(*t, route_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      route_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(withdraw_type_.name()))
  {
    if (congruent(*t, withdraw_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      withdraw_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
  if (auto t = sch.find_type(state_change_type_.name()))
  {
    if (congruent(*t, state_change_type_))
    {
      VAST_VERBOSE("prefers type in schema over default type:", *t);
      state_change_type_ = *t;
    }
    else
    {
      VAST_WARN("ignores incongruent schema type:", t->name());
    }
  }
}

result<event> bgpdumpbinary::extract()
{
  struct format
  {
    time::point timestamp;
    count bgp_type;
    count type;
    count subtype;
    count interface_index;
    count addr_family;
    count old_state;
    count new_state;
    count bgp_length;
    count length;
    count pasnr;
    count med;
    count local_pref;
    std::string msg_type;
    std::string origin;
    std::string as_path_orded;
    std::string community;
    std::string atomic_aggregate;
    vast::address peer_ip_v4;
    vast::address peer_ip_v6;
    vast::address nexthop_v4;
    vast::address nexthop_v6;
    vast::vector as_path;
    vast::vector prefix_v4;
    vast::vector prefix_v6;
    std::tuple<count,vast::address> aggregator;
  };

  // Import the binary file once
  if (!imported)
  {
    bvector = this->import();
    counter = bvector.begin();
    imported = true;
  }

   // parse the file from the last entry until end
   struct format t;
   auto p = bgpbinary_parser{};
   auto l = bvector.end();


  if (counter == l)
  {
    this->done(true);
    return {};
  }

  while (event_queue.size() > 0)
  {
    event current_event = event_queue[event_queue.size() - 1];
    event_queue.pop_back();
    return std::move(current_event);
  }

  auto x = p.parse(counter, l, t);
  record r;

  if (x.timestamp == time::point{time::seconds{0}})
    return {};

  if (x.addr_family == 1)
    prefixCounter = x.prefix_v4.size();
  else if (x.addr_family == 2)
    prefixCounter = x.prefix_v6.size();

  /*----------------- Withdraw Packet ----------------*/
  if (x.msg_type == "W")
  {
    for (int i = 0; i < prefixCounter; ++i)
    {
      packet_stream <<"\nBGP4MP|";

      // Timestamp
      packet_stream << x.timestamp << "|";
      r.emplace_back(x.timestamp);

      // Message Type
      packet_stream << x.msg_type << "|";

      // Withdraw - Source IPv4
      if (x.addr_family == 1)
      {
        packet_stream << to_string(x.peer_ip_v4) << "|";
        r.emplace_back(x.peer_ip_v4);
      }

      // Withdraw - Source IPv6
      else if (x.addr_family == 2)
      {
        packet_stream << to_string(x.peer_ip_v6) << "|";
        r.emplace_back(x.peer_ip_v6);
      }

      // Withdraw - AS Number
      packet_stream << std::dec << x.pasnr << "|";
      r.emplace_back(x.pasnr);

      // Withdraw - Prefix IPv4
      if(x.addr_family == 1)
      {
        packet_stream << x.prefix_v4[i] <<"|";
        r.emplace_back(x.prefix_v4[i]);
      }
      
      // Withdraw - Prefix IPv6
      else if (x.addr_family == 2) 
      {
        packet_stream << x.prefix_v6[i] <<"|";
        r.emplace_back(x.prefix_v6[i]);
      }

      // Withdraw - Event
      event e{{std::move(r), announce_type_}};
      e.timestamp(x.timestamp);
      event_queue.push_back(e);

      // Withdraw - Debug
      packet_string = packet_stream.str();
      //VAST_DEBUG(this, packet_string << "\n");
      packet_stream.str(std::string());
    }

    event current_event = event_queue[event_queue.size() - 1];
    event_queue.pop_back();
    return std::move(current_event);
  }
  /*----------------- Withdraw Packet End-------------*/

  /*----------------- State Packet -------------------*/
  else if (x.msg_type == "STATE")
  {
    packet_stream << "\nBGP4MP|";

    // Timestamp
    packet_stream << x.timestamp << "|";
    r.emplace_back(x.timestamp);

    // Message Type
    packet_stream << x.msg_type << "|";

    // State - Source IPv4
    if (x.addr_family == 1)
    {
      packet_stream << x.peer_ip_v4 << "|";
      r.emplace_back(x.peer_ip_v4);
    }

    // State - Source IPv6
    else if (x.addr_family == 2)
    {
      packet_stream << to_string(x.peer_ip_v6) << "|";
      r.emplace_back(x.peer_ip_v6);
    }

    // State - AS Number
    packet_stream << static_cast<int>(x.pasnr) << "|";
    r.emplace_back(x.pasnr);

    // State - Mode 1
    packet_stream << static_cast<int>(x.old_state) << "|";
    r.emplace_back(x.old_state);

    // State - Mode 2
    packet_stream << static_cast<int>(x.new_state) << "|";
    r.emplace_back(x.new_state);

    packet_string = packet_stream.str();
    //VAST_DEBUG(this, packet_string << "\n");
    packet_stream.str(std::string());
  
    event e{{std::move(r), state_change_type_}};
    e.timestamp(x.timestamp);
    return std::move(e);
   }
  /*----------------- State Packet End----------------*/

  /*----------------- Announce Packet ----------------*/
  else if (x.msg_type == "A")
  {  
    for (int i = 0; i < prefixCounter; ++i)
    {
      packet_stream << "\nBGP4MP|";

      // Timestamp
      packet_stream << x.timestamp << "|";
      r.emplace_back(x.timestamp);

      // Message Type
      packet_stream << x.msg_type << "|";

      // Announce - Source IPv4
      if(x.addr_family == 1)
      {
        packet_stream << x.peer_ip_v4 << "|";
        r.emplace_back(x.peer_ip_v4);
      }

      // Announce - Source IPv6 
      else if (x.addr_family == 2) 
      {
        packet_stream << x.peer_ip_v6 << "|";
        r.emplace_back(x.peer_ip_v6);
      }

      // Announce - AS Number
      packet_stream << x.pasnr << "|";
      r.emplace_back(x.pasnr);

      // Announce - Prefix IPv4
      if(x.addr_family == 1)
      {
        packet_stream << x.prefix_v4[i] << "|";
        r.emplace_back(x.prefix_v4[i]);
      }

      // Announce - Prefix IPv6
      else if (x.addr_family == 2) 
      {
        packet_stream << x.prefix_v6[i] << "|";
        r.emplace_back(x.prefix_v6[i]);
      }

      // Announce - Paths
      packet_stream << to_string(x.as_path) << "|";
      r.emplace_back(x.as_path);

      // Announce - Origin AS
      r.emplace_back(x.as_path[x.as_path.size() - 1]);

      // Announce - Origin
      packet_stream << x.origin << "|";
      r.emplace_back(x.origin);

      //Announce - Next Hop & Community IPv4
      if(x.addr_family == 1)
      {
        packet_stream << to_string(x.nexthop_v4) << "|";
        r.emplace_back(x.nexthop_v4);
      }

      //Announce - Next Hop & Community IPv6
      else if(x.addr_family == 2)
      {
        packet_stream << to_string(x.nexthop_v6) << "|";
        r.emplace_back(x.nexthop_v6);
      }

      // Announce - Local Pref
      packet_stream << x.local_pref << "|";
      r.emplace_back(x.local_pref);

      // Announce - Med
      packet_stream << x.med << "|";
      r.emplace_back(x.med);

      // Announce - Community
      packet_stream << x.community << "|";
      r.emplace_back(x.community);

      // Announce - Atomic Aggregate
      packet_stream << x.atomic_aggregate << "|";
      r.emplace_back(x.atomic_aggregate);

      // Announce - Aggregator
      count route;
      vast::address addr;
      std::tie (route, addr) = x.aggregator;
      if (route != 0)
      {
        packet_stream << "|" << route << " " << addr << "|";
        std::string aggregator = to_string(route) + std::string(" ") + to_string(addr);
        r.emplace_back(aggregator);
      }

      else
        packet_stream << "|";

      // Announce - Event
      event e{{std::move(r), announce_type_}};
      e.timestamp(x.timestamp);
      event_queue.push_back(e);

      // Announce - Debug
      packet_string = packet_stream.str();
      //VAST_DEBUG(this, packet_string << "\n");
      packet_stream.str(std::string());
    }

    event current_event = event_queue[event_queue.size() - 1];
    event_queue.pop_back();
    return std::move(current_event);
    /*----------------- Announce Packet End --------------*/
  }
}
} // namespace source
} // namespace vast
