#include <stdint.h>

static void insertion_sort(uint64_t* data, int count) {
    int i;
    for (i = 1; i < count; ++i) {
        int j = i;

        while (j > 0) {
            if (data[j - 1] > data[j]) {
                data[j - 1] ^= data[j];
                data[j] ^= data[j - 1];
                data[j - 1] ^= data[j];
                --j;
            } else
                break;
        }
    }
}

static void max_heapify(uint64_t *data, int heapSize, int index) {
    int left = (index + 1) * 2 - 1;
    int right = (index + 1) * 2;
    int largest = 0;

    if (left < heapSize && data[left] > data[index])
        largest = left;
    else
        largest = index;

    if (right < heapSize && data[right] > data[largest])
        largest = right;

    if (largest != index) {
        uint64_t temp = data[index];
        data[index] = data[largest];
        data[largest] = temp;

        max_heapify(data, heapSize, largest);
    }
}

static void heap_sort(uint64_t* data, int count) {
    int heapSize = count;
    int p;
    int i;

    for (p = (heapSize - 1) / 2; p >= 0; --p)
        max_heapify(data, heapSize, p);

    for (i = count - 1; i > 0; --i) {
        uint64_t temp = data[i];
        data[i] = data[0];
        data[0] = temp;

        --heapSize;
        max_heapify(data, heapSize, 0);
    }
}

static int partition(uint64_t* data, int left, int right) {
    uint64_t pivot = data[right];
    uint64_t temp;
    int i = left;
    int j;

    for (j = left; j < right; ++j) {
        if (data[j] <= pivot) {
            temp = data[j];
            data[j] = data[i];
            data[i] = temp;
            i++;
        }
    }

    data[right] = data[i];
    data[i] = pivot;

    return i;
}

static void quick_sort(uint64_t* data, int left, int right) {
    if (left < right) {
        int q = partition(data, left, right);
        quick_sort(data, left, q - 1);
        quick_sort(data, q + 1, right);
    }
}

static unsigned int logn(unsigned int n, unsigned int r) {
    return (n > r - 1) ? 1 + logn(n / r, r) : 0;
}

void edfs_sort(uint64_t* data, int count) {
    int partitionSize = partition(data, 0, count - 1);

    if (partitionSize < 16)
        insertion_sort(data, count);
    else
    if (partitionSize >(2 * logn((unsigned int)count, 2)))
        heap_sort(data, count);
    else
        quick_sort(data, 0, count - 1);
}
