#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <mmview.h>
#include <cte.h>
#include <stdbool.h>
#include <fcntl.h>

#include <jpeglib.h>
#include <jerror.h>
#include "cte_mprotect.h"

struct imgRawImage {
	unsigned int numComponents;
	unsigned long int width, height;

	unsigned char* lpData;
};
// #define DEBUG

struct imgRawImage* loadJpegImageFile(char* lpFilename) {
	struct jpeg_decompress_struct info;
	struct jpeg_error_mgr err;

	struct imgRawImage* lpNewImage;

	unsigned long int imgWidth, imgHeight;
	int numComponents;

	unsigned long int dwBufferBytes;
	unsigned char* lpData;

	unsigned char* lpRowBuffer[1];

	FILE* fHandle;

	fHandle = fopen(lpFilename, "rb");
	if(fHandle == NULL) {
		#ifdef DEBUG
			fprintf(stderr, "%s:%u: Failed to read file %s\n", __FILE__, __LINE__, lpFilename);
		#endif
		return NULL; /* ToDo */
	}

	info.err = jpeg_std_error(&err);
	jpeg_create_decompress(&info);

	jpeg_stdio_src(&info, fHandle);
	jpeg_read_header(&info, TRUE);

	jpeg_start_decompress(&info);
	imgWidth = info.output_width;
	imgHeight = info.output_height;
	numComponents = info.num_components;

	#ifdef DEBUG
		fprintf(
			stderr,
			"%s:%u: Reading JPEG with dimensions %lu x %lu and %u components\n",
			__FILE__, __LINE__,
			imgWidth, imgHeight, numComponents
		);
	#endif

	dwBufferBytes = imgWidth * imgHeight * 3; /* We only read RGB, not A */
	lpData = (unsigned char*)malloc(sizeof(unsigned char)*dwBufferBytes);

	lpNewImage = (struct imgRawImage*)malloc(sizeof(struct imgRawImage));
	lpNewImage->numComponents = numComponents;
	lpNewImage->width = imgWidth;
	lpNewImage->height = imgHeight;
	lpNewImage->lpData = lpData;

	/* Read scanline by scanline */
	while(info.output_scanline < info.output_height) {
		lpRowBuffer[0] = (unsigned char *)(&lpData[3*info.output_width*info.output_scanline]);
		jpeg_read_scanlines(&info, lpRowBuffer, 1);
	}

	jpeg_finish_decompress(&info);
	jpeg_destroy_decompress(&info);
	fclose(fHandle);

	return lpNewImage;
}

__attribute__((weak))
struct imgRawImage* loadJpegImageFile_wiped(long mmview, bool wipe, char* lpFilename) {
    long previous = mmview_migrate(mmview);
    // printf("%ld -> %ld\n",  previous, mmview);
    if (wipe) cte_wipe();
    struct imgRawImage *ret = loadJpegImageFile(lpFilename);
    int rc = mmview_migrate(previous); (void) rc;
    // printf("%ld -> %ld (%ld)\n",  mmview, rc, previous);

    return ret;
}

struct imgRawImage* loadJpegImageFile_mprotect(struct cte_range*range, unsigned ranges, char* lpFilename) {
    cte_range_mprotect(range, ranges, PROT_READ);
    struct imgRawImage *ret = loadJpegImageFile(lpFilename);
    cte_range_mprotect(range, ranges, PROT_READ|PROT_EXEC);
    return ret;
}


void freeRawImage(struct imgRawImage *img)  {
    free(img->lpData);
    free(img);
}

int filterGrayscale(
	struct imgRawImage* lpInput,
	struct imgRawImage** lpOutput
    ) {
	unsigned long int i;

	if(lpOutput == NULL) {
		(*lpOutput) = lpInput; /* We will replace our input structure ... */
	} else {
		(*lpOutput) = malloc(sizeof(struct imgRawImage));
		(*lpOutput)->width = lpInput->width;
		(*lpOutput)->height = lpInput->height;
		(*lpOutput)->numComponents = lpInput->numComponents;
		(*lpOutput)->lpData = malloc(sizeof(unsigned char) * lpInput->width*lpInput->height*3);
	}

	for(i = 0; i < lpInput->width*lpInput->height; i=i+1) {
		/* Do a grayscale transformation */
		unsigned char luma = (unsigned char)(
			0.299f * (float)lpInput->lpData[i * 3 + 0]
			+ 0.587f * (float)lpInput->lpData[i * 3 + 1]
			+ 0.114f * (float)lpInput->lpData[i * 3 + 2]
            );
		(*lpOutput)->lpData[i * 3 + 0] = luma;
		(*lpOutput)->lpData[i * 3 + 1] = luma;
		(*lpOutput)->lpData[i * 3 + 2] = luma;
	}

	return 0;
}



int storeJpegImageFile(struct imgRawImage* lpImage, char* lpFilename) {
	struct jpeg_compress_struct info;
	struct jpeg_error_mgr err;

	unsigned char* lpRowBuffer[1];

	FILE* fHandle;

	fHandle = fopen(lpFilename, "wb");
	if(fHandle == NULL) {
		#ifdef DEBUG
			fprintf(stderr, "%s:%u Failed to open output file %s\n", __FILE__, __LINE__, lpFilename);
		#endif
		return 1;
	}

	info.err = jpeg_std_error(&err);
	jpeg_create_compress(&info);

	jpeg_stdio_dest(&info, fHandle);

	info.image_width = lpImage->width;
	info.image_height = lpImage->height;
	info.input_components = 3;
	info.in_color_space = JCS_RGB;

	jpeg_set_defaults(&info);
	jpeg_set_quality(&info, 100, TRUE);

	jpeg_start_compress(&info, TRUE);

	/* Write every scanline ... */
	while(info.next_scanline < info.image_height) {
		lpRowBuffer[0] = &(lpImage->lpData[info.next_scanline * (lpImage->width * 3)]);
		jpeg_write_scanlines(&info, lpRowBuffer, 1);
	}

	jpeg_finish_compress(&info);
	fclose(fHandle);

	jpeg_destroy_compress(&info);
	return 0;
}

#define IMG_ROUNDS  1

#define timespec_diff_ns(ts0, ts)   (((ts).tv_sec - (ts0).tv_sec)*1000LL*1000LL*1000LL + ((ts).tv_nsec - (ts0).tv_nsec))
int main(int argc, char *argv[]) {
    unsigned int repeat = 1;
    if (argc < 2) {
        fprintf(stderr, "%s <image.jpg> [ROUNDS]\n", argv[0]);
        return -1;
    }
    if (argc > 2) {
        repeat = atoi(argv[2]);
    }
    char *imageFile = argv[1];

    struct timespec ts0;
    struct timespec ts1;

    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < IMG_ROUNDS; i++) {
            // 122 ms on my machine
            // Wikimedia Image of the Day: 15th December
            // Intercession Church on the Nerl in Bogolyubovo near Vladimir, Russia
            struct imgRawImage *image = loadJpegImageFile(imageFile);

            struct imgRawImage *grayscale = NULL;
            filterGrayscale(image, &grayscale);

            storeJpegImageFile(grayscale, "/dev/shm/grayscale.jpg");
            freeRawImage(grayscale);
            freeRawImage(image);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "img,plain,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, IMG_ROUNDS);
    }

    ////////////////////////////////////////////////////////////////
    // With Wiping

    // And now with mmview and libcte
    cte_init(0);
    //cte_init(0);
    cte_mmview_unshare();
    long img_mmview = mmview_create();
    long previous;
    int fd;

    loadJpegImageFile_wiped(img_mmview, true, argv[1]);
    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < IMG_ROUNDS; i++) {
            // Wikimedia Image of the Day: 15th December
            // Intercession Church on the Nerl in Bogolyubovo near Vladimir, Russia
            struct imgRawImage *image = loadJpegImageFile_wiped(img_mmview, false, imageFile);

            // As loading the image allocates a 41 MiB buffer, it uses
            // mmap. With mmviews, these have to be synchronized => We
            // are a little bit slower here.

            struct imgRawImage *grayscale = NULL;
            filterGrayscale(image, &grayscale);

            storeJpegImageFile(grayscale, "/dev/shm/grayscale.jpg");
            freeRawImage(grayscale);
            freeRawImage(image);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "img,migrate,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, IMG_ROUNDS);
    }

    struct cte_range *ranges = malloc(sizeof(struct cte_range) * 10000); 
    fd = open("img.migrate.dict", O_RDWR|O_CREAT|O_TRUNC, 0644);
    cte_dump_state(fd, 0);
    previous = mmview_migrate(img_mmview); 
    cte_dump_state(fd, CTE_DUMP_FUNCS|CTE_DUMP_TEXTS);
    unsigned range_count = cte_get_wiped_ranges(ranges);
    mmview_migrate(previous);
    if (mmview_delete(img_mmview) == -1) die("mmview_delete");


    ////////////////////////////////////////////////////////////////
    // With mprotect
    unsigned mprotect_count=0, mprotect_bytes=0;
    cte_range_stat(ranges, range_count, mprotect_count, mprotect_bytes);
    printf("mprotect Ranges: %d, %d\n", mprotect_count, mprotect_bytes);


    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < IMG_ROUNDS; i++) {
            // Wikimedia Image of the Day: 15th December
            // Intercession Church on the Nerl in Bogolyubovo near Vladimir, Russia
            struct imgRawImage *image = loadJpegImageFile_mprotect(ranges, range_count, imageFile);

            struct imgRawImage *grayscale = NULL;
            filterGrayscale(image, &grayscale);

            storeJpegImageFile(grayscale, "/dev/shm/grayscale.jpg");
            freeRawImage(grayscale);
            freeRawImage(image);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "img,mprotect,%f,%d,%d,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, IMG_ROUNDS,
                mprotect_count, mprotect_bytes);
    }
    
    close(fd);

    return 0;
}
