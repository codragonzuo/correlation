#include <iostream>
#include "rdkafkacpp.h"

void ParserEvent(char * strEvent);

class ExampleDeliveryReportCb : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message &message) {
        /* If message.err() is non-zero the message delivery failed permanently
         * for the message. */
        if (message.err())
            std::cerr << "% Message delivery failed: " << message.errstr() << std::endl;
        else
            std::cerr << "% Message delivered to topic " << message.topic_name() <<
            " [" << message.partition() << "] at offset " <<
            message.offset() << std::endl;
    }
};


RdKafka::Conf *m_conf;
RdKafka::Conf *m_tconf;
RdKafka::Producer *producer;

int producer_init() {

    std::string brokers = "192.168.20.45:6669";


    RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

    std::string errstr;

    /* Set bootstrap broker(s) as a comma-separated list of
     * host or host:port (default port 9092).
     * librdkafka will use the bootstrap brokers to acquire the full
     * set of brokers from the cluster. */
    if (conf->set("bootstrap.servers", brokers, errstr) !=
        RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return 1;
    }


    ExampleDeliveryReportCb ex_dr_cb;

    if (conf->set("dr_cb", &ex_dr_cb, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return 1;
    }

    /*
     * Create producer instance.
     */
    producer = RdKafka::Producer::create(conf, errstr);
    if (!producer) {
        std::cerr << "Failed to create producer: " << errstr << std::endl;
        return 1;
    }

    delete conf;

    return 0;
}


int sendMessage(std::string msg)
{
    std::string topic = "attack";
    producer->poll(0);

retry:
    RdKafka::ErrorCode err =
            producer->produce(
                /* Topic name */
                topic,
                /* Any Partition: the builtin partitioner will be
                 * used to assign the message to a topic based
                 * on the message key, or random partition if
                 * the key is not set. */
                RdKafka::Topic::PARTITION_UA,
                /* Make a copy of the value */
                RdKafka::Producer::RK_MSG_COPY /* Copy payload */,
                /* Value */
                const_cast<char *>(msg.c_str()), msg.size(),
                /* Key */
                NULL, 0,
                /* Timestamp (defaults to current time) */
                0,
                /* Message headers, if any */
                NULL,
                /* Per-message opaque value passed to
                 * delivery report */
                NULL);

    if (err != RdKafka::ERR_NO_ERROR) 
	{
        std::cerr << "% Failed to produce to topic " << topic << ": " <<
                RdKafka::err2str(err) << std::endl;

        if (err == RdKafka::ERR__QUEUE_FULL) {
                /* If the internal queue is full, wait for
                 * messages to be delivered and then retry.
                 * The internal queue represents both
                 * messages to be sent and messages that have
                 * been sent or failed, awaiting their
                 * delivery report callback to be called.
                 *
                 * The internal queue is limited by the
                 * configuration property
                 * queue.buffering.max.messages */
                producer->poll(100/*block for max 1000ms*/);
                goto retry;

        }
        else {
            std::cerr << "% Enqueued message (" << msg.size() << " bytes) " <<
                "for topic " << topic << std::endl;
        }

        /* Wait for final messages to be delivered or fail.
         * flush() is an abstraction over poll() which
         * waits for all messages to be delivered. */
        //std::cerr << "% Flushing final messages..." << std::endl;
        //producer->flush(10 * 1000 /* wait for max 10 seconds */);

        if (producer->outq_len() > 0)
            std::cerr << "% " << producer->outq_len() <<
            " message(s) were not delivered" << std::endl;
    }
    return 0;

}



/*
int testmain(int argc, char **argv) {
    producer_test();
    std::cin.get();
    return 1;
}
*/
/*******************************************************************************************************************************/

static int run = 1;
static bool exit_eof = false;
static int eof_cnt = 0;
static int partition_cnt = 0;
static int verbosity = 1;
static long msg_cnt = 0;
static int64_t msg_bytes = 0;

static void print_time() {
    /*
#ifndef _WIN32
    struct timeval tv;
    char buf[64];
    gettimeofday(&tv, NULL);
    strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    fprintf(stderr, "%s.%03d: ", buf, (int)(tv.tv_usec / 1000));
#else
    SYSTEMTIME lt = { 0 };
    GetLocalTime(&lt);
    // %Y-%m-%d %H:%M:%S.xxx:
    fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03d: ",
        lt.wYear, lt.wMonth, lt.wDay,
        lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
#endif
    */
}

class ExampleEventCb : public RdKafka::EventCb {
public:
    void event_cb(RdKafka::Event &event) {

        print_time();

        switch (event.type())
        {
        case RdKafka::Event::EVENT_ERROR:
            if (event.fatal()) {
                std::cerr << "FATAL ";
                run = 0;
            }
            std::cerr << "ERROR (" << RdKafka::err2str(event.err()) << "): " <<
                event.str() << std::endl;
            break;

        case RdKafka::Event::EVENT_STATS:
            std::cerr << "\"STATS\": " << event.str() << std::endl;
            break;

        case RdKafka::Event::EVENT_LOG:
            fprintf(stderr, "LOG-%i-%s: %s\n",
                event.severity(), event.fac().c_str(), event.str().c_str());
            break;

        case RdKafka::Event::EVENT_THROTTLE:
            std::cerr << "THROTTLED: " << event.throttle_time() << "ms by " <<
                event.broker_name() << " id " << (int)event.broker_id() << std::endl;
            break;

        default:
            std::cerr << "EVENT " << event.type() <<
                " (" << RdKafka::err2str(event.err()) << "): " <<
                event.str() << std::endl;
            break;
        }
    }
};


class ExampleRebalanceCb : public RdKafka::RebalanceCb {
private:
    static void part_list_print(const std::vector<RdKafka::TopicPartition*>&partitions) {
        for (unsigned int i = 0; i < partitions.size(); i++)
            std::cerr << partitions[i]->topic() <<
            "[" << partitions[i]->partition() << "], ";
        std::cerr << "\n";
    }

public:
    void rebalance_cb(RdKafka::KafkaConsumer *consumer,
        RdKafka::ErrorCode err,
        std::vector<RdKafka::TopicPartition*> &partitions) {
        std::cerr << "RebalanceCb: " << RdKafka::err2str(err) << ": ";

        part_list_print(partitions);

        if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
            consumer->assign(partitions);
            partition_cnt = (int)partitions.size();
        }
        else {
            consumer->unassign();
            partition_cnt = 0;
        }
        eof_cnt = 0;
    }
};


void msg_consume(RdKafka::Message* message, void* opaque) {
    switch (message->err()) {
    case RdKafka::ERR__TIMED_OUT:
        break;

    case RdKafka::ERR_NO_ERROR:
        /* Real message */
        msg_cnt++;
        msg_bytes += message->len();
        if (verbosity >= 3)
            std::cerr << "Read msg at offset " << message->offset() << std::endl;
        RdKafka::MessageTimestamp ts;
        ts = message->timestamp();
        if (verbosity >= 2 &&
            ts.type != RdKafka::MessageTimestamp::MSG_TIMESTAMP_NOT_AVAILABLE) {
            std::string tsname = "?";
            if (ts.type == RdKafka::MessageTimestamp::MSG_TIMESTAMP_CREATE_TIME)
                tsname = "create time";
            else if (ts.type == RdKafka::MessageTimestamp::MSG_TIMESTAMP_LOG_APPEND_TIME)
                tsname = "log append time";
            std::cout << "Timestamp: " << tsname << " " << ts.timestamp << std::endl;
        }
        if (verbosity >= 2 && message->key()) {
            std::cout << "Key: " << *message->key() << std::endl;
        }
        if (verbosity >= 1) {
            //printf("%.*s\n", static_cast<int>(message->len()), static_cast<const char *>(message->payload()));
            ParserEvent((char *)(message->payload()));
        }
        break;

    case RdKafka::ERR__PARTITION_EOF:
        /* Last message */
        if (exit_eof && ++eof_cnt == partition_cnt) {
            std::cerr << "%% EOF reached for all " << partition_cnt <<
                " partition(s)" << std::endl;
            run = 0;
        }
        break;

    case RdKafka::ERR__UNKNOWN_TOPIC:
    case RdKafka::ERR__UNKNOWN_PARTITION:
        std::cerr << "Consume failed: " << message->errstr() << std::endl;
        run = 0;
        break;

    default:
        /* Errors */
        std::cerr << "Consume failed: " << message->errstr() << std::endl;
        run = 0;
    }
}





int Testmain() {
    std::string brokers = "localhost";
    std::string errstr;
    std::string topic_str;
    std::string mode;
    std::string debug;
    std::vector<std::string> topics;
    //bool do_conf_dump = false;
//  int opt;

    /*
     * Create configuration objects
     */
    RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
    RdKafka::Conf *tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);

    ExampleRebalanceCb ex_rebalance_cb;
    conf->set("rebalance_cb", &ex_rebalance_cb, errstr);

    conf->set("enable.partition.eof", "true", errstr);
    conf->set("group.id", "correlation", errstr);
    //for (; optind < argc; optind++)
    //  topics.push_back(std::string(argv[optind]));
    topics.push_back("sideout");

    brokers = "192.168.20.45:6669";
    conf->set("metadata.broker.list", brokers, errstr);

    ExampleEventCb ex_event_cb;
    conf->set("event_cb", &ex_event_cb, errstr);

    conf->set("default_topic_conf", tconf, errstr);
    delete tconf;


    RdKafka::KafkaConsumer *consumer = RdKafka::KafkaConsumer::create(conf, errstr);
    if (!consumer) {
        std::cerr << "Failed to create consumer: " << errstr << std::endl;
        exit(1);
    }

    delete conf;
    std::cout << "% Created consumer " << consumer->name() << std::endl;

    /*
     * Subscribe to topics
     */
    RdKafka::ErrorCode err = consumer->subscribe(topics);
    if (err) {
        std::cerr << "Failed to subscribe to " << topics.size() << " topics: "
            << RdKafka::err2str(err) << std::endl;
        exit(1);
    }

    /*
     * Consume messages
     */
    while (1) {
        RdKafka::Message *msg = consumer->consume(1000);
        msg_consume(msg, NULL);
        delete msg;
    }


    /*
     * Stop consumer
     */
    consumer->close();
    delete consumer;
    std::cerr << "% Consumed " << msg_cnt << " messages ("
        << msg_bytes << " bytes)" << std::endl;

    /*
     * Wait for RdKafka to decommission.
     * This is not strictly needed (with check outq_len() above), but
     * allows RdKafka to clean up all its resources before the application
     * exits so that memory profilers such as valgrind wont complain about
     * memory leaks.
     */
    RdKafka::wait_destroyed(5000);

    return 0;
}
