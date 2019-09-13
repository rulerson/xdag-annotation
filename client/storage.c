/* локальное хранилище, T13.663-T14.596 $DVS:time$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "storage.h"
#include "init.h"
#include "hash.h"
#include "utils/log.h"
#include "utils/utils.h"

#define STORAGE_DIR0 "storage%s"
#define STORAGE_DIR0_ARGS(t) (g_xdag_testnet ? "-testnet" : "")
#define STORAGE_DIR1 STORAGE_DIR0 DELIMITER "%02x"
#define STORAGE_DIR1_ARGS(t) STORAGE_DIR0_ARGS(t), (int)((t) >> 40)
#define STORAGE_DIR2 STORAGE_DIR1 DELIMITER "%02x"
#define STORAGE_DIR2_ARGS(t) STORAGE_DIR1_ARGS(t), (int)((t) >> 32) & 0xff
#define STORAGE_DIR3 STORAGE_DIR2 DELIMITER "%02x"
#define STORAGE_DIR3_ARGS(t) STORAGE_DIR2_ARGS(t), (int)((t) >> 24) & 0xff
#define STORAGE_FILE STORAGE_DIR3 DELIMITER "%02x.dat"
#define STORAGE_FILE_ARGS(t) STORAGE_DIR3_ARGS(t), (int)((t) >> 16) & 0xff
#define SUMS_FILE "sums.dat"

static pthread_mutex_t storage_mutex = PTHREAD_MUTEX_INITIALIZER;
static int in_adding_all = 0;


/*
 path: sum文件名
 pos: 更新sum文件中第几个位置的的sum值，[0, 256)
 sum: 被更新的sum值
 add: 1: 累加上去，0: 覆盖原始值。
 */
static int correct_storage_sum(const char *path, int pos, const struct xdag_storage_sum *sum, int add)
{
    struct xdag_storage_sum sums[256];
    FILE *f = xdag_open_file(path, "r+b");

    if (f) {
        if (fread(sums, sizeof(struct xdag_storage_sum), 256, f) != 256) {
            xdag_close_file(f);
            xdag_err("Storage: sums file %s corrupted", path);
            return -1;
        }
        rewind(f);
    } else {
        f = xdag_open_file(path, "wb");
        if (!f) {
            xdag_err("Storage: can't create file %s", path);
            return -1;
        }
        memset(sums, 0, sizeof(sums));
    }

    if (!add) {
        if (sums[pos].size == sum->size && sums[pos].sum == sum->sum) {
            xdag_close_file(f);
            return 0;
        }

        if (sums[pos].size || sums[pos].sum) {
            sums[pos].size = sums[pos].sum = 0;
            xdag_err("Storage: corrupted, sums file %s, pos %x", path, pos);
        }
    }

    sums[pos].size += sum->size;
    sums[pos].sum += sum->sum;

    if (fwrite(sums, sizeof(struct xdag_storage_sum), 256, f) != 256) {
        xdag_close_file(f);
        xdag_err("Storage: can't write file %s", path);
        return -1;
    }

    xdag_close_file(f);

    return 1;
}

/*
 递归向上的更新t时间对应时间片的所有关联sum文件
 */
static int correct_storage_sums(xtime_t t, const struct xdag_storage_sum *sum, int add)
{
    char path[256] = {0};

    sprintf(path, STORAGE_DIR3 DELIMITER SUMS_FILE, STORAGE_DIR3_ARGS(t));
    int res = correct_storage_sum(path, (t >> 16) & 0xff, sum, add);
    if (res <= 0)
        return res;

    sprintf(path, STORAGE_DIR2 DELIMITER SUMS_FILE, STORAGE_DIR2_ARGS(t));
    res = correct_storage_sum(path, (t >> 24) & 0xff, sum, 1);
    if (res <= 0)
        return res;

    sprintf(path, STORAGE_DIR1 DELIMITER SUMS_FILE, STORAGE_DIR1_ARGS(t));
    res = correct_storage_sum(path, (t >> 32) & 0xff, sum, 1);
    if (res <= 0)
        return res;

    sprintf(path, STORAGE_DIR0 DELIMITER SUMS_FILE, STORAGE_DIR0_ARGS(t));
    res = correct_storage_sum(path, (t >> 40) & 0xff, sum, 1);
    if (res <= 0)
        return res;

    return 0;
}

/* Saves the block to local storage, returns its number or -1 in case of error */
int64_t xdag_storage_save(const struct xdag_block *b)
{
    struct xdag_storage_sum s;
    char path[256] = {0};
    int64_t res;

    if (in_adding_all) {
        return -1;
    }

    sprintf(path, STORAGE_DIR0, STORAGE_DIR0_ARGS(b->field[0].time));
    xdag_mkdir(path);

    sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(b->field[0].time));
    xdag_mkdir(path);

    sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(b->field[0].time));
    xdag_mkdir(path);

    sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(b->field[0].time));
    xdag_mkdir(path);

    sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(b->field[0].time));

    pthread_mutex_lock(&storage_mutex);

    FILE *f = xdag_open_file(path, "ab");
    if (f) {
        fseek(f, 0, SEEK_END);
        res = ftell(f);
        fwrite(b, sizeof(struct xdag_block), 1, f);
        xdag_close_file(f);
        s.size = sizeof(struct xdag_block);
        s.sum = 0;

        for (int j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
            s.sum += ((uint64_t *)b)[j];
        }

        if (correct_storage_sums(b->field[0].time, &s, 1)) {
            res = -1;
        }
    } else {
        res = -1;
    }

    pthread_mutex_unlock(&storage_mutex);

    return res;
}

/* reads a block and its number from the local repository; writes it to the buffer or returns a permanent reference, 0 in case of error */
struct xdag_block *xdag_storage_load(xdag_hash_t hash, xtime_t time, uint64_t pos, struct xdag_block *buf)
{
    xdag_hash_t hash0;
    char path[256] = {0};

    sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(time));

    pthread_mutex_lock(&storage_mutex);

    FILE *f = xdag_open_file(path, "rb");
    if (f) {
        if (fseek(f, pos, SEEK_SET) < 0 || fread(buf, sizeof(struct xdag_block), 1, f) != 1) {
            buf = 0;
        }
        xdag_close_file(f);
    } else {
        buf = 0;
    }

    pthread_mutex_unlock(&storage_mutex);

    if (buf) {
        xdag_hash(buf, sizeof(struct xdag_block), hash0);
        if (memcmp(hash, hash0, sizeof(xdag_hashlow_t))) {
            buf = 0;
        }
    }

    if (!buf) {
        xdag_blocks_reset();
    }

    return buf;
}

#define bufsize (0x100000 / sizeof(struct xdag_block))     // 2<<20 / 2<<9 = 2**11 = 2048

static int sort_callback(const void *l, const void *r)
{
    struct xdag_block **L = (struct xdag_block **)l, **R = (struct xdag_block **)r;

    if ((*L)->field[0].time < (*R)->field[0].time)
        return -1;
    if ((*L)->field[0].time > (*R)->field[0].time)
        return 1;

    return 0;
}

/* Calls a callback for all blocks from the repository that are in specified time interval; returns the number of blocks
 */
uint64_t xdag_load_blocks(xtime_t start_time, xtime_t end_time, void *data, void *(*callback)(void *, void *))
{
    struct xdag_block *buf, *pbuf[bufsize];
    struct xdag_storage_sum s;
    char path[256] = {0};

    uint64_t sum = 0, pos = 0, mask;
    int64_t i, j, k, todo;

    s.size = s.sum = 0;

    buf = malloc(bufsize * sizeof(struct xdag_block));  // 1M, bufsize=2048
    if (buf == NULL) {
        xdag_fatal("malloc failed [function xdag_load_blocks]");
        return 0;
    }

    /*
     一次读取最多2048个block，从start_time搜索到end_time中所有block，对所有的block执行callback，在block的transport_header中放上block在文件中的position(cursor sequence)
     */
    while (start_time < end_time) {
        sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(start_time)); 

        pthread_mutex_lock(&storage_mutex);

        FILE *f = xdag_open_file(path, "rb");           // read block data file for time index of start_time
        if (f) {
            if (fseek(f, pos, SEEK_SET) < 0)
                todo = 0;
            else
                todo = fread(buf, sizeof(struct xdag_block), bufsize, f);
            xdag_close_file(f);
        } else {
            todo = 0;
        }

        pthread_mutex_unlock(&storage_mutex);

        uint64_t pos0 = pos;

        for (i = k = 0; i < todo; ++i, pos += sizeof(struct xdag_block)) {
            if (buf[i].field[0].time >= start_time && buf[i].field[0].time < end_time) {
                s.size += sizeof(struct xdag_block);

                for (j = 0; j < sizeof(struct xdag_block) / sizeof(uint64_t); ++j) {
                    s.sum += ((uint64_t *)(buf + i))[j];    
                    // todo: maybe-bug，应该在外层循环做这个事，以为当前代码不会出现时间在block中间的情况，不会触发问题。
                }

                pbuf[k++] = buf + i;
            }
        }

        if (k) {    // 按照时间升序排序block
            qsort(pbuf, k, sizeof(struct xdag_block *), sort_callback);
        }

        for (i = 0; i < k; ++i) {
            pbuf[i]->field[0].transport_header = pos0 + ((uint8_t *)pbuf[i] - (uint8_t *)buf);      // block's cursor sequence in block file
            if (callback(pbuf[i], data)) {
                free(buf);
                return sum;
            }
            sum++;
        }

        if (todo != bufsize) {
            /*
             顺换读取当前时间片对应的block文件，读到了末尾，或者当前时间片block文件不存在。
             */
            if (f) {   
                /* 
                 当前时间片block文件存在，且读到了末尾，做一次sum更新
                 maybe-bug：这里sum好像是有问题的，有可能漏掉当前时间片中在start_time之前的block。
                 为何要在这里覆盖更新一次sum文件？
                 */
                pthread_mutex_lock(&storage_mutex);

                int res = correct_storage_sums(start_time, &s, 0);

                pthread_mutex_unlock(&storage_mutex);

                if (res)
                    break;

                s.size = s.sum = 0;
                mask = (1l << 16) - 1;
            } else if (sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(start_time)), xdag_file_exists(path)) { 
                // 当前时间片block文件不存在，但是当前时间片第3级目录存在，直接跳到下一个时间片文件。
                mask = (1l << 16) - 1;
            } else if (sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(start_time)), xdag_file_exists(path)) {
                // 当前时间片第3级目录不存在，但是当前时间片第2级目录存在，直接跳到下一个3级目录。
                mask = (1l << 24) - 1;
            } else if (sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(start_time)), xdag_file_exists(path)) {
                // 当前时间片第2级目录不存在，但是当前时间片第1级目录存在，直接跳到下一个2级目录。
                mask = (1ll << 32) - 1;
            } else {
                // 当前时间片第1级目录不存在，直接跳到下一个1级目录。（0级目录为storage目录，一定存在。）
                mask = (1ll << 40) - 1;
            }

            start_time |= mask;
            start_time++;           // 设置为下一个时间片0时

            pos = 0;
        }
    }

    free(buf);
    return sum;
}

/* places the sums of blocks in 'sums' array, blocks are filtered by interval from start_time to end_time, splitted to 16 parts;
 * end - start should be in form 16^k
 * (original russian comment is unclear too) */

/*
 获取指定时间片之间block的sum值
 
 这里对start_time和end_time做了特殊限制，只能有两种取值方法。
 1. 刚好把一个目录下256个时间片的sum全部取走
 2. 或者，取这个目录下256个时间片的其中16个，而且只能在256个里面每隔16个时间片，取一次16个时间，也就是说，必须用16等分。
 */
int xdag_load_sums(xtime_t start_time, xtime_t end_time, struct xdag_storage_sum sums[16])
{
    struct xdag_storage_sum buf[256];
    char path[256] = {0};
    int i, level;

    end_time -= start_time;
    if (!end_time || end_time & (end_time - 1) || end_time & 0xFFFEEEEEEEEFFFFFl)   // 校验end_time - start_time 在时间片跨度上，必须是16的k次方
        return -1;

    for (level = -6; end_time; level++, end_time >>= 4)
        ;

    // 这段是用来判断，到底取第几个等级目录下的sum文件。
    if (level < 2) {
        sprintf(path, STORAGE_DIR3 DELIMITER SUMS_FILE, STORAGE_DIR3_ARGS(start_time & 0xffffff000000l));
    } else if (level < 4) {
        sprintf(path, STORAGE_DIR2 DELIMITER SUMS_FILE, STORAGE_DIR2_ARGS(start_time & 0xffff00000000l));
    } else if (level < 6) {
        sprintf(path, STORAGE_DIR1 DELIMITER SUMS_FILE, STORAGE_DIR1_ARGS(start_time & 0xff0000000000l));
    } else {
        sprintf(path, STORAGE_DIR0 DELIMITER SUMS_FILE, STORAGE_DIR0_ARGS(start_time & 0x000000000000l));
    }

    FILE *f = xdag_open_file(path, "rb");
    if (f) {
        fread(buf, sizeof(struct xdag_storage_sum), 256, f);
        xdag_close_file(f);
    } else {
        memset(buf, 0, sizeof(buf));
    }

    if (level & 1) {    // 取整个256个时间片的sum，从第0个开始，每16个聚合成一个sum，总共聚合出16个新的sum。
        memset(sums, 0, 16 * sizeof(struct xdag_storage_sum));

        for (i = 0; i < 256; ++i) {
            sums[i >> 4].size += buf[i].size, sums[i >> 4].sum += buf[i].sum;
        }
    } else {    // 只取256中16个时间片的sum，原样复制sum。
        memcpy(sums, buf + (start_time >> ((level + 4) * 4) & 0xf0), 16 * sizeof(struct xdag_storage_sum));
    }

    return 1;
}

/* completes work with the storage */
void xdag_storage_finish(void)
{
    pthread_mutex_lock(&storage_mutex);
}
