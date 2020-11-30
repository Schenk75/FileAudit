import request from '@/utils/request-test'

export function getList(table, query) {
  return request({
    url: '/table/' + table,
    method: 'get',
    params: query
  })
}

export function deleteRecord(table, query) {
  return request({
    url: '/table/' + table,
    method: 'get',
    params: query
  })
}