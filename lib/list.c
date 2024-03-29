#include <list.h>

void list_init(struct list *head)
{
	head->next = head;
	head->prev = head;
}

void list_insert_before(struct list *before, struct list *node)
{
	node->prev = before;
	node->next = before->next;

	before->next->prev = node;
	before->next = node;
}

void list_insert_after(struct list *after, struct list *node)
{
	node->next = after;
	node->prev = after->prev;

	after->prev->next = node;
	after->prev = node;
}

void list_remove(struct list *node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;

	node->next = node;
	node->prev = node;
}

void list_push(struct list *head, struct list *node)
{
	list_insert_before(head, node);
}

void list_push_left(struct list *head, struct list *node)
{
	list_insert_after(head, node);
}

struct list *list_pop(struct list *head)
{
	struct list *node;

	if (head->prev == head)
		return NULL;

	node = head->prev;
	list_remove(node);

	return node;
}

struct list *list_pop_left(struct list *head)
{
	struct list *node;

	if (head->next == head)
		return NULL;

	node = head->next;
	list_remove(node);

	return node;
}

void list_advance_head(struct list *head)
{
		struct list *temp = head->next->next;

        head->next->prev = head->prev;
        head->next->next = head;

        head->prev->next = head->next;

        head->prev = head->next;
        head->next = temp;
        head->next->prev = head;
}

int list_len(struct list *head) 
{
	struct list *node;
	int count = 0;
	list_foreach(head, node) {
		count++;
	}
	return count;
}