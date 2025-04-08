#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.pb-c.h"

int main() {
    // 创建并初始化 Person 实例

    Test__Person person = TEST__PERSON__INIT;
    person.name = "Alice";
    person.id = 123;
    person.status = TEST__STATUS__OK;
    person.address = malloc(sizeof(Test__Address));
    test__address__init(person.address);  // 正确初始化嵌套的 Address 消息结构
    person.address->street  = "123 Main St";
    person.address->city    = "Hometown";
    person.address->zip_code = "12345";
    person.n_emails = 1;
    person.emails = malloc(sizeof(char*));
    person.emails[0] = "alice@example.com";

    // 序列化消息
    size_t len = test__person__get_packed_size(&person);
    uint8_t *buf = malloc(len);
    test__person__pack(&person, buf);

    // 打印序列化的二进制数据
    printf("Serialized data:\n");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    // 反序列化消息
    Test__Person *unpacked_person = test__person__unpack(NULL, len, buf);
    if (unpacked_person == NULL) {
        fprintf(stderr, "Error unpacking incoming message\n");
        return 1;
    }

    // 打印反序列化后的消息内容
    printf("\nUnpacked Person:\n");
    printf("Name: %s\n", unpacked_person->name);
    printf("ID: %d\n", unpacked_person->id);
    printf("Status: %d\n", unpacked_person->status);
    printf("Address: %s, %s, %s\n",
           unpacked_person->address->street,
           unpacked_person->address->city,
           unpacked_person->address->zip_code);
    printf("Email: %s\n", unpacked_person->emails[0]);

    // 清理
    free(person.address);
    free(person.emails);
    test__person__free_unpacked(unpacked_person, NULL);
    free(buf);

    return 0;
}

