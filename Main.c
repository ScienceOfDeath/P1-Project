#include "Keyexchange.h"
#include <stdio.h> 

int main() {
    char* shared_secret = NULL;
    int choice;

    while(1) {
        printf("\n Choose function \n 1. Generate new key (requires same network) \n 2. Encrypt message \n 3. Decrypt message \n 4. send an encrypted message \n 5. receive an encrypted message \n 6. Create key locally from password \n 7. Exit\n");
        printf("Enter choice: ");
        if (scanf("%d", &choice) != 1) {
            while(getchar() != '\n'); // Clear buffer
            continue;
        }

        switch (choice) {
            case 1:
                if (shared_secret != NULL) {
                    OPENSSL_free(shared_secret);
                }
                shared_secret = start_key_exchange();
                break;
            case 2:
                encrypt_message(shared_secret);
                break;
            case 3:
                decrypt_message(shared_secret);
                break;
            case 4:
               send_encrypted_message(shared_secret);
                break;
            case 5:
               receive_encrypted_message(shared_secret);
                break;
            case 6:
                shared_secret = create_key_from_password();
                break;
            case 7:
                if (shared_secret != NULL) {
                    OPENSSL_free(shared_secret);
                }
                WSACleanup();
                exit(0);
                break;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
    return 0;
}
